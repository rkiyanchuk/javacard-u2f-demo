"""Generate a P-256 key, push the private scalar to the card, keep only the
public key on the host.

One shot per applet instance: the applet refuses a second INS 01. Reinstalling
the CAP destroys the on-card key -- delete card_pub.pem and re-run.
"""

import sys
from pathlib import Path

from card import SW_CONDITIONS_NOT_SATISFIED, SW_OK, connect, select, send
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PUB_PATH = Path(__file__).resolve().parents[2] / "card_pub.pem"


def main():
    if PUB_PATH.exists():
        sys.exit(
            f"{PUB_PATH.name} already exists -- it verifies a provisioned card. "
            "Move it aside only together with a CAP reinstall."
        )

    key = ec.generate_private_key(ec.SECP256R1())
    scalar = key.private_numbers().private_value.to_bytes(32, "big")

    conn = connect()
    select(conn)
    _, sw = send(conn, 0x01, scalar)

    if sw == SW_CONDITIONS_NOT_SATISFIED:
        sys.exit(
            "already provisioned -- card key is fixed, "
            "delete and reinstall the applet to reset"
        )
    if sw != SW_OK:
        raise RuntimeError(f"provisioning failed: SW={sw:04X}")

    PUB_PATH.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"provisioned OK -- public key saved to {PUB_PATH.name}")


if __name__ == "__main__":
    main()
