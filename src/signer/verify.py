"""Challenge the card, verify the signature it returns.

The host never signs: the private key lives only on the card. card_pub.pem
holds the matching public key, written by provision.py.

    uv run python src/signer/verify.py [challenge-hex]
"""

import os
import sys
from pathlib import Path

from card import SW_OK, connect, select, send
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PUB_PATH = Path(__file__).resolve().parents[2] / "card_pub.pem"


def main():
    if not PUB_PATH.exists():
        sys.exit(f"{PUB_PATH.name} not found -- run src/signer/provision.py first")
    pub = serialization.load_pem_public_key(PUB_PATH.read_bytes())
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        sys.exit(f"{PUB_PATH.name} does not hold an EC public key")

    challenge = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else os.urandom(32)

    conn = connect(wait=30)
    select(conn)
    sig, sw = send(conn, 0x02, challenge)
    if sw != SW_OK:
        raise RuntimeError(f"signing failed: SW={sw:04X}")

    print(f"challenge ({len(challenge)} B): {challenge.hex()}")
    print(f"signature ({len(sig)} B): {sig.hex()}")

    # The card hashes the challenge with SHA-256 and signs the hash, so verify
    # against the raw challenge; ECDSA(SHA256()) redoes the same hash. The
    # card returns a DER-encoded signature, which is the format verify() takes.
    try:
        pub.verify(sig, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        sys.exit("VERIFICATION FAILED")
    print("VERIFIED")


if __name__ == "__main__":
    main()
