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

from ..postgres import load_postgres_plugin

from .crypto import (
    encode_pack_message,
    decode_pack_message_outer,
    decode_pack_message_payload,
)
from .error import WalletError
from .indy import IndyWallet
from .util import b58_to_bytes


CHACHAPOLY_KEY_LEN = 32
CHACHAPOLY_NONCE_LEN = 12
CHACHAPOLY_TAG_LEN = 16
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

    @property
    def connection(self) -> asyncpg.pool.PoolAcquireContext:
        """Return a connection handle."""
        return self.handle.acquire()

    async def release(self, conn: asyncpg.Connection):
        if conn:
            await self.handle.release(conn)

    async def setup(self):
        await self.handle

    async def fetch_keys(
        self,
        key_pass: str,
        key_deriv_method: str = IndyWallet.KEY_DERIVATION_ARGON2I_MOD,
    ) -> StorageKeys:
        async with self.connection as conn:
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

            if key_deriv_method in (
                IndyWallet.KEY_DERIVATION_ARGON2I_INT,
                IndyWallet.KEY_DERIVATION_ARGON2I_MOD,
            ):
                moderate = key_deriv_method == IndyWallet.KEY_DERIVATION_ARGON2I_MOD
                key_pass_bin = key_pass.encode("ascii")
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
        value_key = cls.decrypt_merged(row["key"], keys.value_key)
        value = cls.decrypt_merged(row["value"], value_key) if row["value"] else None
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

    async def fetch_items(self, keys: StorageKeys):
        async with self.connection as conn:
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

    async def fetch_record_value(
        self, keys: StorageKeys, record_type: str, record_name: str
    ):
        enc_type = base64.b64encode(
            self.encrypt_merged(
                record_type.encode("ascii"), keys.type_key, keys.item_hmac_key
            )
        )
        enc_name = base64.b64encode(
            self.encrypt_merged(
                record_name.encode("ascii"), keys.name_key, keys.item_hmac_key
            )
        )
        async with self.connection as conn:
            row = await conn.fetchrow(
                "SELECT value, key FROM items WHERE type=$1 AND name=$2",
                enc_type,
                enc_name,
            )
            if not row:
                return None
            value_key = self.decrypt_merged(row["key"], keys.value_key)
            value = (
                self.decrypt_merged(row["value"], value_key) if row["value"] else None
            )
            return value


class IndyPgWallet(IndyWallet):
    """Postgres implementation of Indy wallet."""

    DEFAULT_STORAGE_TYPE = "postgres_storage"

    def __init__(self, config: dict = None):
        """Initialize the Indy postgres wallet instance."""
        load_postgres_plugin()
        super().__init__(config)
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
        self._storage_keys: StorageKeys = None
        self.key_cache = {}
        self.test = 1

    @property
    def pool(self):
        return self._pool

    async def get_storage_keys(self) -> StorageKeys:
        if not self._storage_keys:
            await self._pool.setup()
            self._storage_keys = await self._pool.fetch_keys(
                self._key, self._key_derivation_method
            )
        return self._storage_keys

    async def get_private_key(self, keys: StorageKeys, verkey: str) -> bytes:
        if verkey in self.key_cache:
            return self.key_cache[verkey]
        value = await self.pool.fetch_record_value(keys, "Indy::Key", verkey)
        if value:
            self.key_cache[verkey] = b58_to_bytes(json.loads(value)["signkey"])
            return self.key_cache[verkey]

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
        keys = await self.get_storage_keys()
        if self.test:
            from_secret = await self.get_private_key(keys, from_verkey)
            if from_secret:
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
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
            keys = await self.get_storage_keys()
            wrapper, recips, is_auth = decode_pack_message_outer(enc_message)
            for recip_vk, sender_cek in recips.items():
                recip_secret = await self.get_private_key(keys, recip_vk)
                if recip_secret:
                    payload, sender_vk = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: decode_pack_message_payload(
                            wrapper, sender_cek, recip_secret
                        ),
                    )
                    return payload, sender_vk, recip_vk
            raise ValueError(
                "No corresponding recipient key found in {}".format(tuple(recips))
            )
        return await super().unpack_message(enc_message)
