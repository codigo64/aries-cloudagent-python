import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.support.agent import DemoAgent, default_genesis_txns
from runners.support.utils import (
    log_json,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
    require_indy,
)


LOGGER = logging.getLogger(__name__)


class AliceAgent(DemoAgent):
    def __init__(
        self, http_port: int, admin_port: int, no_auto: bool = False, **kwargs
    ):
        super().__init__(
            "Alice Agent",
            http_port,
            admin_port,
            prefix="Alice",
            extra_args=[]
            if no_auto
            else [
                "--auto-accept-invites",
                "--auto-accept-requests",
                "--auto-store-credential",
            ],
            seed=None,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = asyncio.Future()
        self.cred_state = {}

    async def receive_invite(self, invite, accept: str = "auto"):
        result = await self.admin_POST(
            "/connections/receive-invitation", invite, params={"accept": accept}
        )
        self.connection_id = result["connection_id"]
        return self.connection_id

    async def accept_invite(self, conn_id: str):
        await self.admin_POST(f"/connections/{conn_id}/accept-invitation")

    async def establish_inbound(self, conn_id: str, router_conn_id: str):
        await self.admin_POST(
            f"/connections/{conn_id}/establish-inbound/{router_conn_id}"
        )

    async def detect_connection(self):
        await self._connection_ready

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        if message["connection_id"] == self.connection_id:
            if message["state"] == "active" and not self._connection_ready.done():
                self.log("Connected")
                self._connection_ready.set_result(True)

    async def handle_issue_credential(self, message):
        state = message["state"]
        credential_exchange_id = message["credential_exchange_id"]
        prev_state = self.cred_state.get(credential_exchange_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[credential_exchange_id] = state

        self.log(
            "Credential: state =",
            state,
            ", credential_exchange_id =",
            credential_exchange_id,
        )

        if state == "offer_received":
            log_status("#15 After receiving credential offer, send credential request")
            await self.admin_POST(
                f"/issue-credential/records/{credential_exchange_id}/send-request"
            )

        elif state == "credential_acked":
            cred_id = message["credential_id"]
            self.log(f"Stored credential {cred_id} in wallet")
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            resp = await self.admin_GET(f"/credential/{cred_id}")
            log_json(resp, label="Credential details:")
            log_json(
                message["credential_request_metadata"],
                label="Credential request metadata:",
            )
            self.log("credential_id", message["credential_id"])
            self.log("credential_definition_id", message["credential_definition_id"])
            self.log("schema_id", message["schema_id"])

    async def handle_present_proof(self, message):
        state = message["state"]
        presentation_exchange_id = message["presentation_exchange_id"]
        presentation_request = message["presentation_request"]

        log_msg(
            "Presentation: state =",
            state,
            ", presentation_exchange_id =",
            presentation_exchange_id,
        )

        if state == "request_received":
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )

            # include self-attested attributes (not included in credentials)
            credentials_by_reft = {}
            revealed = {}
            self_attested = {}
            predicates = {}

            # select credentials to provide for the proof
            credentials = await self.admin_GET(
                f"/present-proof/records/{presentation_exchange_id}/credentials"
            )
            if credentials:
                for row in credentials:
                    for referent in row["presentation_referents"]:
                        if referent not in credentials_by_reft:
                            credentials_by_reft[referent] = row

            for referent in presentation_request["requested_attributes"]:
                if referent in credentials_by_reft:
                    revealed[referent] = {
                        "cred_id": credentials_by_reft[referent]["cred_info"][
                            "referent"
                        ],
                        "revealed": True,
                    }
                else:
                    self_attested[referent] = "my self-attested value"

            for referent in presentation_request["requested_predicates"]:
                if referent in credentials_by_reft:
                    predicates[referent] = {
                        "cred_id": credentials_by_reft[referent]["cred_info"][
                            "referent"
                        ],
                        "revealed": True,
                    }

            log_status("#25 Generate the proof")
            request = {
                "requested_predicates": predicates,
                "requested_attributes": revealed,
                "self_attested_attributes": self_attested,
            }

            log_status("#26 Send the proof to X")
            await self.admin_POST(
                (
                    "/present-proof/records/"
                    f"{presentation_exchange_id}/send-presentation"
                ),
                request,
            )

    async def handle_basicmessages(self, message):
        self.log("Received message:", message["content"])


class RoutingAgent(DemoAgent):
    def __init__(
        self, http_port: int, admin_port: int, no_auto: bool = False, **kwargs
    ):
        super().__init__(
            "Routing Agent",
            http_port,
            admin_port,
            prefix="Router",
            extra_args=[]
            if no_auto
            else [
                "--auto-accept-invites",
                "--auto-accept-requests",
                "--auto-store-credential",
            ],
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = asyncio.Future()
        self.cred_state = {}

    async def get_invite(self, accept: str = "auto"):
        result = await self.admin_POST(
            "/connections/create-invitation", params={"accept": accept}
        )
        self.connection_id = result["connection_id"]
        return result["invitation"]


async def input_invitation(agent, routing_agent=None):
    async for details in prompt_loop("Invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                json.loads(details)
                break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        if routing_agent:
            log_msg("Connect Alice to router ...")
            log_msg("... get invite from router ...")
            router_invite = await routing_agent.get_invite()
            print(router_invite)
            log_msg("... alice receive invite ...")
            agent_router_conn_id = await agent.receive_invite(router_invite)
            log_msg("... wait for connection to router ...")
            await asyncio.wait_for(agent.detect_connection(), 30)
            log_msg("... connected!")

        if routing_agent:
            log_msg("Connect Alice to Faber via router ...")
            agent.connection_id = await agent.receive_invite(details, accept="manual")
            await agent.establish_inbound(agent.connection_id, agent_router_conn_id)
            await agent.accept_invite(agent.connection_id)
            await asyncio.wait_for(agent.detect_connection(), 30)
        else:
            log_msg("Connect Alice to Faber ...")
            agent.connection_id = await agent.receive_invite(details)

        log_msg("Connection:", agent.connection_id)

        await asyncio.wait_for(agent.detect_connection(), 30)


async def main(start_port: int, no_auto: bool = False, show_timing: bool = False, routing: bool = False):

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None
    alice_router = None

    try:
        log_status("#7 Provision an agent and wallet, get back configuration details")
        agent = AliceAgent(
            start_port,
            start_port + 1,
            genesis_data=genesis,
            no_auto=no_auto,
            timing=show_timing,
        )
        await agent.listen_webhooks(start_port + 2)

        if routing:
            alice_router = RoutingAgent(
                start_port + 6, start_port + 7, genesis_data=genesis, timing=show_timing
            )
            #await alice_router.listen_webhooks(start_port + 8)
            await alice_router.register_did()

        with log_timer("Startup duration:"):
            if alice_router:
                await alice_router.start_process()
            await agent.start_process()
        log_msg("Admin url is at:", agent.admin_url)
        log_msg("Endpoint url is at:", agent.endpoint)
        log_msg("Router Admin url is at:", alice_router.admin_url)
        log_msg("Router Endpoint url is at:", alice_router.endpoint)

        log_status("#9 Input faber.py invitation details")
        await input_invitation(agent, alice_router)

        async for option in prompt_loop(
            "(3) Send Message (4) Input New Invitation (X) Exit? [3/4/X]: "
        ):
            if option is None or option in "xX":
                break
            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await agent.admin_POST(
                        f"/connections/{agent.connection_id}/send-message",
                        {"content": msg},
                    )
            elif option == "4":
                # handle new invitation
                log_status("Input new invitation details")
                await input_invitation(agent, alice_router)

        if show_timing:
            timing = await agent.fetch_timing()
            if timing:
                for line in agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = True
        try:
            if agent:
                await agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating Alice agent:")
            terminated = False
        try:
            if alice_router:
                await alice_router.terminate()
        except Exception:
            LOGGER.exception("Error terminating Routing agent:")
            terminated = False

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Runs an Alice demo agent.")
    parser.add_argument("--no-auto", action="store_true", help="Disable auto issuance")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8030,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )
    parser.add_argument(
        "--routing", action="store_true", help="Enable inbound routing demonstration"
    )
    parser.add_argument(
        "--timing", action="store_true", help="Enable timing information"
    )
    args = parser.parse_args()

    require_indy()

    try:
        asyncio.get_event_loop().run_until_complete(
            main(args.port, args.no_auto, args.timing, args.routing)
        )
    except KeyboardInterrupt:
        os._exit(1)
