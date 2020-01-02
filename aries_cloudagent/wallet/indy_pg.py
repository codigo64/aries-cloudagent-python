"""Postgres variant of Indy wallet."""

import asyncio
import base64
import hashlib
import hmac
import json
from typing import Sequence
from urllib.parse import urlparse

import asyncpg
import msgpack
import nacl.bindings
import nacl.encoding
import nacl.pwhash
import nacl.utils

from .crypto import (
    encode_pack_message,
    decode_pack_message_outer,
    decode_pack_message_payload,
)
from .error import WalletError
from .indy import IndyWallet
from .util import b58_to_bytes


CHACHAPOLY_KEY_LEN = nacl.bindings.crypto_aead_chacha20poly1305_ietf_KEYBYTES
CHACHAPOLY_NONCE_LEN = nacl.bindings.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
CHACHAPOLY_TAG_LEN = nacl.bindings.crypto_aead_chacha20poly1305_ietf_ABYTES
ENCRYPTED_KEY_LEN = CHACHAPOLY_NONCE_LEN + CHACHAPOLY_KEY_LEN + CHACHAPOLY_TAG_LEN


def hmac_sha256(data: bytes, key: bytes):
    return hmac.HMAC(key, data, hashlib.sha256).digest()


# def sha256(data: bytes):
#     return nacl.hash.sha256(data, nacl.encoding.RawEncoder)

# def hmac_sha256(data: bytes, key: bytes):
#     B = key + bytes(64 - len(key))
#     B_i = bytes(b ^ 0x36 for b in B)
#     B_o = bytes(b ^ 0x5C for b in B)
#     return sha256(B_o + sha256(B_i + data))

# hmac = hmac_sha256(b"The quick brown fox jumps over the lazy dog", b"key")
# chek = bytes.fromhex(
#   "F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8")
# print("hmac", hmac.hex())
# print("chek", chek.hex())
# assert hmac == chek


class StorageKeys:
    key_order = (
        "type_key",
        "name_key",
        "value_key",
        "item_hmac_key",
        "tag_name_key",
        "tag_value_key",
        "tag_hmac_key",
    )

    def __init__(self, keys: Sequence[bytes]):
        self.keys = dict(zip(self.key_order, keys))

    def __getattr__(self, attr: str):
        if attr in self.key_order:
            return self.keys[attr]
        raise AttributeError(f"Unknown key: {attr}")


class WalletConnectionPool:
    def __init__(self, config: dict, creds: dict):
        """Initialize the connection handler."""
        self._config: dict = config
        self._creds: dict = creds
        self._handle: asyncpg.pool.Pool = None
        self._init_lock = asyncio.Lock()
        self.check_config()

    def check_config(self):
        """Check that the config parameters are provided."""
        config, creds = self._config, self._creds
        if not config:
            raise WalletError("Missing postgres config")
        if not config.get("name"):
            raise WalletError("Missing postgres database name")
        if not config.get("url"):
            raise WalletError("Missing postgres URL")

        if (
            not creds
            or not creds.get("admin_account")
            or not creds.get("admin_password")
        ):
            raise WalletError("Missing postgres credentials")

    @property
    def handle(self) -> asyncpg.pool.Pool:
        if not self._handle:
            url = self._config["url"]
            if "://" not in url:
                url = f"http://{url}"
            parts = urlparse(url)
            self._handle = asyncpg.create_pool(
                host=parts.hostname,
                port=parts.port or 5432,
                user=self._creds["admin_account"],
                password=self._creds["admin_password"],
                database=self._config["name"],
                min_size=1,
                max_size=5,
            )
        return self._handle

    def connection(self) -> asyncpg.pool.PoolAcquireContext:
        """Return a connection handle."""
        return self.handle.acquire()

    async def release(self, conn: asyncpg.Connection):
        if conn:
            await self.handle.release(conn)

    async def setup(self):
        await self.handle


class WalletSession:
    def __init__(
        self,
        pool: WalletConnectionPool,
        key_pass: str,
        key_deriv_method: str = IndyWallet.KEY_DERIVATION_ARGON2I_MOD,
    ):
        """Initialize a new wallet session."""
        self._key_pass = key_pass
        self._key_deriv_method = key_deriv_method
        self._loop = asyncio.get_event_loop()
        self._pool = pool
        self._private_key_cache = {}
        self._record_type_cache = {}
        self._storage_keys: StorageKeys = None

    @property
    def pool(self):
        return self._pool

    @property
    def storage_keys(self) -> StorageKeys:
        return self._storage_keys

    async def run_crypto(self, func):
        return await self._loop.run_in_executor(None, func)

    async def fetch_storage_keys(self) -> StorageKeys:
        async with self.pool.connection() as conn:
            metadata_row = await conn.fetchrow("SELECT * FROM metadata")
            metadata_b64 = metadata_row["value"]
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json)
            keys_enc = bytes(metadata["keys"])
            salt = (
                bytes(metadata["master_key_salt"])
                if "master_key_salt" in metadata
                else None
            )

            if self._key_deriv_method in (
                IndyWallet.KEY_DERIVATION_ARGON2I_INT,
                IndyWallet.KEY_DERIVATION_ARGON2I_MOD,
            ):
                moderate = (
                    self._key_deriv_method == IndyWallet.KEY_DERIVATION_ARGON2I_MOD
                )
                key_pass_bin = self._key_pass.encode("ascii")
                master_key = nacl.pwhash.argon2i.kdf(
                    CHACHAPOLY_KEY_LEN,
                    key_pass_bin,
                    salt[:16],  # Indy creates a salt that is too large
                    nacl.pwhash.argon2i.OPSLIMIT_MODERATE
                    if moderate
                    else nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE,
                    nacl.pwhash.argon2i.MEMLIMIT_MODERATE
                    if moderate
                    else nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE,
                )
            else:
                raise WalletError("Unsupported key derivation method")

            keys_mpk = self.decrypt_merged(keys_enc, master_key)
            keys_lst = msgpack.unpackb(keys_mpk)
            return StorageKeys(keys_lst)

    @classmethod
    def decrypt_merged(cls, enc_value: bytes, key: bytes, b64: bool = False) -> bytes:
        if b64:
            enc_value = base64.b64decode(enc_value)
        nonce, ciphertext = (
            enc_value[:CHACHAPOLY_NONCE_LEN],
            enc_value[CHACHAPOLY_NONCE_LEN:],
        )
        return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext, None, nonce, key
        )

    def decrypt_record_value(
        cls, enc_record_key: bytes, enc_record_value: bytes, value_key: bytes
    ):
        if not enc_record_value:
            return None
        record_key = cls.decrypt_merged(enc_record_key, value_key)
        return cls.decrypt_merged(enc_record_value, record_key)

    @classmethod
    def decrypt_tags(cls, tags: list, name_key: bytes, value_key: bytes = None):
        for tag in tags:
            name = cls.decrypt_merged(tag[0], name_key).decode("utf-8")
            value = (
                cls.decrypt_merged(tag[1], value_key).decode("utf-8")
                if value_key
                else tag[1]
            )
            yield name, value

    @classmethod
    def decrypt_item(cls, row: dict, keys: StorageKeys):
        value = cls.decrypt_record_value(row["key"], row["value"], keys.value_key)
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        result = {
            "type": cls.decrypt_merged(row["type"], keys.type_key, True).decode(
                "utf-8"
            ),
            "name": cls.decrypt_merged(row["name"], keys.name_key, True).decode(
                "utf-8"
            ),
            "value": value,
            "tags_enc": dict(
                cls.decrypt_tags(row["tags_enc"], keys.tag_name_key, keys.tag_value_key)
                if row["tags_enc"]
                else ()
            ),
            "tags_text": dict(
                cls.decrypt_tags(row["tags_text"], keys.tag_name_key)
                if row["tags_text"]
                else ()
            ),
        }
        return result

    @classmethod
    def encrypt_merged(cls, data: bytes, value_key: bytes, hmac_key: bytes = None):
        if hmac_key:
            nonce = hmac_sha256(data, hmac_key)[:CHACHAPOLY_NONCE_LEN]
        else:
            nonce = nacl.utils.random(CHACHAPOLY_NONCE_LEN)
        ciphertext = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            data, None, nonce, value_key
        )
        return nonce + ciphertext

    async def encrypt_record_type(self, record_type: str):
        keys = self._storage_keys
        if record_type not in self._record_type_cache:
            self._record_type_cache[record_type] = await self.run_crypto(
                lambda: base64.b64encode(
                    self.encrypt_merged(
                        record_type.encode("ascii"), keys.type_key, keys.item_hmac_key
                    )
                ),
            )
        return self._record_type_cache[record_type]

    async def encrypt_record_name(self, record_name: str):
        keys = self._storage_keys
        return await self.run_crypto(
            lambda: base64.b64encode(
                self.encrypt_merged(
                    record_name.encode("ascii"), keys.name_key, keys.item_hmac_key
                )
            ),
        )

    async def fetch_items(self, keys: StorageKeys = None):
        if not keys:
            keys = self._storage_keys
        async with self.pool.connection() as conn:
            rows = await conn.fetch(
                """
                SELECT id, type, name, value, key,
                (SELECT array_agg(tags_enc)
                FROM (SELECT name, value from tags_encrypted
                WHERE item_id=items.id) tags_enc) tags_enc,
                (SELECT array_agg(tags_text)
                FROM (SELECT name, value from tags_plaintext
                WHERE item_id=items.id) tags_text) tags_text
                FROM items
            """
            )
            for row in rows:
                result = self.decrypt_item(row, keys)
                print(result)
                if result["type"] == "Indy::Key":
                    print("got type", row["type"].hex())
                    print("got name", row["name"].hex())
                # pprint.pprint(result, indent=2)
                # print()

    async def fetch_record_value(self, record_type: str, record_name: str):
        keys = self._storage_keys
        enc_type = await self.encrypt_record_type(record_type)
        enc_name = await self.encrypt_record_name(record_name)
        async with self.pool.connection() as conn:
            row = await conn.fetchrow(
                "SELECT value, key FROM items WHERE type=$1 AND name=$2",
                enc_type,
                enc_name,
            )
            if not row:
                return None
            if row["value"]:
                return await self.run_crypto(
                    lambda: self.decrypt_record_value(
                        row["key"], row["value"], keys.value_key
                    ),
                )

    async def get_private_key(self, verkey: str) -> bytes:
        if verkey in self._private_key_cache:
            return self._private_key_cache[verkey]
        value = await self.fetch_record_value("Indy::Key", verkey)
        if value:
            self._private_key_cache[verkey] = b58_to_bytes(json.loads(value)["signkey"])
            return self._private_key_cache[verkey]

    async def __aenter__(self):
        await self._pool.setup()
        if not self._storage_keys:
            self._storage_keys = await self.fetch_storage_keys()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class IndyPgWallet(IndyWallet):
    """Postgres implementation of Indy wallet."""

    DEFAULT_STORAGE_TYPE = "postgres_storage"

    def __init__(self, config: dict = None):
        """Initialize the Indy postgres wallet instance."""
        if "storage_type" in config:
            del config["storage_type"]
        super(IndyPgWallet, self).__init__(config)
        if not self._storage_config:
            raise WalletError("Missing postgres wallet config")
        try:
            pg_config = json.loads(self._storage_config)
        except json.JSONDecodeError:
            raise WalletError("Error parsing postgres wallet config")
        pg_config["name"] = self.name
        try:
            pg_creds = json.loads(self._storage_creds) if self._storage_creds else None
        except json.JSONDecodeError:
            raise WalletError("Error parsing postgres wallet credentials")
        self._pool = WalletConnectionPool(pg_config, pg_creds)
        self._session: WalletSession = None
        self.test = 1

    @property
    def pool(self):
        return self._pool

    def wallet_session(self) -> WalletSession:
        if not self._session:
            self._session = WalletSession(
                self.pool, self._key, self._key_derivation_method
            )
        return self._session

    async def print_all(self):
        keys = await self.get_storage_keys()
        await self.pool.fetch_items(keys)

    async def pack_message(
        self, message: str, to_verkeys: Sequence[str], from_verkey: str = None
    ) -> bytes:
        """
        Pack a message for one or more recipients.

        Args:
            message: The message to pack
            to_verkeys: The verkeys to pack the message for
            from_verkey: The sender verkey

        Returns:
            The packed message

        """
        if self.test:
            async with self.wallet_session() as session:
                from_secret = await session.get_private_key(from_verkey)
                if from_secret:
                    result = await session.run_crypto(
                        lambda: encode_pack_message(
                            message, map(b58_to_bytes, to_verkeys), from_secret
                        ),
                    )
                else:
                    raise WalletError("failed loading private key")
        else:
            result = await super().pack_message(message, to_verkeys, from_verkey)
        return result

    async def unpack_message(self, enc_message: bytes) -> (str, str, str):
        """
        Unpack a message.

        Args:
            enc_message: The encrypted message

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        """
        if self.test:
            wrapper, recips, is_auth = decode_pack_message_outer(enc_message)
            async with self.wallet_session() as session:
                for recip_vk, sender_cek in recips.items():
                    recip_secret = await session.get_private_key(recip_vk)
                    if recip_secret:
                        (
                            payload,
                            sender_vk,
                        ) = await session.run_crypto(
                            lambda: decode_pack_message_payload(
                                wrapper, sender_cek, recip_secret
                            ),
                        )
                        return payload, sender_vk, recip_vk
            raise ValueError(
                "No corresponding recipient key found in {}".format(tuple(recips))
            )
        return await super().unpack_message(enc_message)
