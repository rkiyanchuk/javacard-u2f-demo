"""Set or change the FIDO2 applet's PIN over PC/SC.

A fresh applet has no PIN; `demo.py` needs one for user verification.

    uv run python src/fido2/set_pin.py [--pin 123456]
    uv run python src/fido2/set_pin.py --old 123456 --pin 654321
"""

import argparse
import sys

from fido2.ctap2.base import Ctap2
from fido2.ctap2.pin import ClientPin

from demo import open_device


class Args(argparse.Namespace):
    pin: str = "123456"
    old: str | None = None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--pin", default=Args.pin, help="new PIN")
    _ = parser.add_argument("--old", help="current PIN, to change an existing one")
    args = parser.parse_args(namespace=Args())
    pin, old = args.pin, args.old

    ctap = Ctap2(open_device())
    client_pin = ClientPin(ctap)
    pin_set = bool(ctap.info.options.get("clientPin"))

    if not pin_set:
        client_pin.set_pin(pin)
        print(f"PIN set to {pin}")
    elif old is not None:
        client_pin.change_pin(old, pin)
        print(f"PIN changed to {pin}")
    else:
        print("PIN already set; pass --old to change it", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
