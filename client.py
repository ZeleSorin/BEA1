import asyncio
from hashlib import sha256

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import VariablePayloadWID as VariablePayload
from ipv8_service import IPv8


EMAIL = "szele@student.tudelft.nl"
GITHUB_URL = "https://github.com/ZeleSorin/BEA1#"
NONCE = 211495735  # TODO: fill in your mined nonce here

SERVER_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
COMMUNITY_ID = "2c1cc6e35ff484f99ebdfb6108477783c0102881"


class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]


class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


def verify_pow(email, github_url, nonce):
    data = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    h = sha256(data + nonce.to_bytes(8, "big")).digest()
    ok = h[0] == 0 and h[1] == 0 and h[2] == 0 and h[3] < 16
    print(f"PoW check: {'PASS' if ok else 'FAIL'} -- {h.hex()}")
    return ok


class Lab1Community(Community):
    community_id = bytes.fromhex(COMMUNITY_ID)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.server_key_bytes = bytes.fromhex(SERVER_KEY_HEX)
        self.submitted = False
        self.register_task("find_server", self.find_server, interval=5.0, delay=2.0)

    def find_server(self):
        for peer in self.get_peers():
            key_hex = peer.public_key.key_to_bin().hex()
            print(f"  peer: {key_hex[:20]}...")
            if peer.public_key.key_to_bin() == self.server_key_bytes and not self.submitted:
                self.submitted = True
                self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, NONCE))
                print("Submission sent to server, waiting for response...")
                self.cancel_pending_task("find_server")

    @lazy_wrapper(ResponsePayload)
    def on_response(self, _peer, payload):
        print(f"Server response: success={payload.success}, message='{payload.message}'")


async def main():
    if not verify_pow(EMAIL, GITHUB_URL, NONCE):
        print("PoW verification failed -- fix NONCE before connecting.")
        return

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my key", "curve25519", "my_key.pem")
    builder.add_overlay(
        "Lab1Community",
        "my key",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    print("IPv8 started, searching for server peer...")

    community = ipv8.get_overlay(Lab1Community)
    assert community is not None
    for i in range(24):
        await asyncio.sleep(10)
        peers = community.get_peers()
        print(f"[{(i+1)*10}s] peers in community: {len(peers)}")
        if community.submitted:
            break

    await ipv8.stop()


asyncio.run(main())
