import json

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

import pytest

try:
    from indy.libindy import _cdll

    _cdll()
except ImportError:
    pytest.skip(
        "skipping Indy-specific tests: python module not installed",
        allow_module_level=True,
    )
except OSError:
    pytest.skip(
        "skipping Indy-specific tests: shared library not loaded",
        allow_module_level=True,
    )

from aries_cloudagent.ledger.indy import (
    IndyLedger,
    GENESIS_TRANSACTION_PATH,
    ClosedPoolError,
    LedgerTransactionError,
    DuplicateSchemaError,
)

from aries_cloudagent.verifier.indy import IndyVerifier


class TestIndyVerifier(AsyncTestCase):
    def test_init(self):
        verifier = IndyVerifier("wallet")
        assert verifier.wallet == "wallet"

    @async_mock.patch("indy.anoncreds.verifier_verify_proof")
    async def test_verify_presentation(self, mock_verify):
        mock_verify.return_value = "val"

        verifier = IndyVerifier("wallet")
        verified = await verifier.verify_presentation(
            "presentation_request", "presentation", "schemas", "credential_definitions"
        )

        mock_verify.assert_called_once_with(
            json.dumps("presentation_request"),
            json.dumps("presentation"),
            json.dumps("schemas"),
            json.dumps("credential_definitions"),
            json.dumps({}),
            json.dumps({}),
        )

        assert verified == "val"
