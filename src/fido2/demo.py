"""Run both WebAuthn ceremonies against the FIDO2 applet over PC/SC.

Three parties take part, all in this process except the card:

- relying party: `Fido2Server`, the website's backend. Issues challenges and
  verifies what comes back.
- client: `Fido2Client`, the browser. Builds clientData and talks CTAP2.
- authenticator: the card. The only party holding the private key.

Registration creates a credential; authentication proves possession of it.
A clean run proves the applet is a working CTAP2 authenticator without a
browser. macOS WebAuthn cannot see a CCID reader; for a browser ceremony, tap
the card to an iPhone running Safari (not an in-app webview).

Set the PIN first with `set_pin.py`; the demo prompts for it.

    uv run python src/fido2/demo.py [--keep] [--verbose]
"""

import argparse
import getpass
import os
import sys
from typing import override

from fido2.client import Fido2Client, UserInteraction
from fido2.ctap2.base import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.pcsc import CtapPcscDevice
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestedCredentialData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

import ctap_trace as style
from ctap_trace import TracingDevice

RP = PublicKeyCredentialRpEntity(id="demo.example", name="JavaCard FIDO2 Demo")
ORIGIN = "https://demo.example"


class Args(argparse.Namespace):
    keep: bool = False
    verbose: bool = False


class Interaction(UserInteraction):
    """Supplies the PIN; the base class already allows UV."""

    def __init__(self, pin: str):
        self.pin: str = pin

    @override
    def request_pin(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> str:
        return self.pin


def open_device() -> TracingDevice:
    return TracingDevice(
        next(CtapPcscDevice.list_devices(os.environ.get("GP_READER", "Contact Reader")))
    )


def credential_manager(ctap: Ctap2, pin: str) -> CredentialManagement:
    """A fresh PIN token per call: the applet spends one on every write."""
    client_pin = ClientPin(ctap)
    token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap, client_pin.protocol, token)


# fido2 leaves the `extensions` parameter and the opaque `state` untyped, hence
# the pyright suppressions on the Fido2Server calls below.


def register(server: Fido2Server, client: Fido2Client) -> AttestedCredentialData:
    """Registration ceremony: create a discoverable credential on the card."""
    print(style.bold("\n== Registration =="))

    # 1. Relying party: challenge + RP/user identity + requirements.
    options, state = server.register_begin(  # pyright: ignore[reportUnknownMemberType, reportAny]
        PublicKeyCredentialUserEntity(
            id=os.urandom(16), name="demo", display_name="Demo User"
        ),
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    print(
        f"1. {style.rp('relying party:')} challenge {options.public_key.challenge.hex()}"
    )

    # 2. Client -> authenticator: authenticatorMakeCredential. The card makes a
    #    new key pair and returns the public key in attested authenticator data.
    print(
        f"2. {style.client('client')} -> {style.card('authenticator')}: makeCredential"
    )
    response = client.make_credential(options.public_key)
    print(f"   {style.card('authenticator:')} key pair created")

    # 3. Relying party: check challenge, origin, RP ID hash, flags, attestation;
    #    store the credential ID and public key.
    auth_data = server.register_complete(state, response)  # pyright: ignore[reportUnknownMemberType, reportAny]
    credential = auth_data.credential_data
    if credential is None:
        raise RuntimeError("authenticator returned no attested credential data")
    cred_id = credential.credential_id
    print(f"3. {style.rp('relying party:')} verified; credential {cred_id.hex()}")
    print(f"   flags {auth_data.flags!r}, {len(cred_id)}-byte credential ID")
    return credential


def authenticate(
    server: Fido2Server, client: Fido2Client, credential: AttestedCredentialData
) -> None:
    """Authentication ceremony: the card signs a fresh challenge."""
    print(style.bold("\n== Authentication =="))

    # 1. Relying party: challenge. No allowCredentials: the credential is
    #    discoverable, so the card finds it by RP ID (usernameless login).
    options, state = server.authenticate_begin(  # pyright: ignore[reportUnknownMemberType, reportAny]
        user_verification=UserVerificationRequirement.REQUIRED
    )
    print(
        f"1. {style.rp('relying party:')} challenge {options.public_key.challenge.hex()}"
    )

    # 2. Client -> authenticator: authenticatorGetAssertion. The card signs
    #    authenticator data || SHA-256(clientDataJSON) with the credential key.
    print(f"2. {style.client('client')} -> {style.card('authenticator')}: getAssertion")
    response = client.get_assertion(options.public_key).get_response(0)
    sign_count = response.response.authenticator_data.counter
    print(f"   {style.card('authenticator:')} signed with {response.raw_id.hex()}")

    # 3. Relying party: verify the signature with the stored public key.
    _ = server.authenticate_complete(state, [credential], response)  # pyright: ignore[reportUnknownMemberType, reportAny]
    print(
        f"3. {style.rp('relying party:')} signature verified; sign count {sign_count}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    _ = parser.add_argument(
        "--keep", action="store_true", help="leave the demo credential on the card"
    )
    _ = parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every CTAP2 command and reply, decoded",
    )
    args = parser.parse_args(namespace=Args())

    dev = open_device()
    ctap = Ctap2(dev)
    info = ctap.info
    print(f"{style.card('authenticator:')} {dev}")
    print(f"  versions:   {', '.join(info.versions)}")
    print(f"  extensions: {', '.join(info.extensions)}")
    print(f"  aaguid:     {info.aaguid.hex()}")
    if not info.options.get("clientPin"):
        raise RuntimeError("no PIN set; run src/fido2/set_pin.py first")
    pin = getpass.getpass("card PIN: ")

    server = Fido2Server(RP, attestation=AttestationConveyancePreference.NONE)
    client = Fido2Client(
        dev,
        client_data_collector=dev.client_data_collector(ORIGIN),
        user_interaction=Interaction(pin),
    )

    dev.enabled = args.verbose
    credential = register(server, client)
    authenticate(server, client, credential)

    print(style.bold("\n== Cleanup =="))
    meta = credential_manager(ctap, pin).get_metadata()
    stored = int(meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT])  # pyright: ignore[reportAny]
    print(f"discoverable credentials stored: {stored}")
    if not args.keep:
        descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY, id=credential.credential_id
        )
        credential_manager(ctap, pin).delete_cred(descriptor)
        print("demo credential deleted")

    print(style.bold("\nOK"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
