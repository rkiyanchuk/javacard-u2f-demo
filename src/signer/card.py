"""PC/SC plumbing shared by provision.py and verify.py.

Run directly, it probes the card for the applications this repo installs by
sending a SELECT for each AID, printing every raw command and response:

    uv run python src/signer/card.py

9000 means the card routed the SELECT to an installed application, 6A82 means
no application has that AID. Listing everything (`gp --list`) needs GET STATUS
over an authenticated GlobalPlatform secure channel; SELECT needs none.
"""

import os

from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException
from smartcard.System import readers

APPLET_AID = bytes.fromhex("F0DEC0DE0101")
SW_OK = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985


def connect(wait=0):
    """Connect to the reader named by $GP_READER, else the first contact reader.

    The R502 exposes five PC/SC readers (contact, contactless, SPY, SAM1,
    SAM2), so the pick is always explicit. With `wait` > 0, an empty reader
    blocks up to that many seconds for a card instead of failing at once.
    """
    available = readers()
    if not available:
        raise RuntimeError("no PC/SC readers found")

    wanted = os.environ.get("GP_READER")
    if wanted:
        matches = [r for r in available if wanted in str(r)]
    else:
        matches = [r for r in available if "Contact Reader" in str(r)]
    if not matches:
        raise RuntimeError(
            "no matching reader; set GP_READER to one of: "
            + ", ".join(str(r) for r in available)
        )

    reader = matches[0]
    conn = reader.createConnection()
    try:
        conn.connect()
        return conn
    except NoCardException:
        if wait <= 0:
            raise

    print(f"insert or tap a card on {reader} (waiting {wait} s)...")
    try:
        CardRequest(readers=[reader], timeout=wait).waitforcard()
    except CardRequestTimeoutException:
        raise RuntimeError(f"no card on {reader} within {wait} s") from None
    conn.connect()
    return conn


def _transmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    if sw1 == 0x61:  # T=0 wants an explicit GET RESPONSE
        data, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
    return bytes(data), (sw1 << 8) | sw2


def select(conn):
    """SELECT the applet by AID. Raises unless the card answers 9000."""
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)]) + APPLET_AID + b"\x00"
    _, sw = _transmit(conn, apdu)
    if sw != SW_OK:
        raise RuntimeError(f"SELECT {APPLET_AID.hex()} failed: SW={sw:04X}")


def send(conn, ins, data):
    """Send CLA 80 / INS / P1P2 0000 with `data`. Returns (response, sw)."""
    if not 1 <= len(data) <= 255:
        raise ValueError(f"data must be 1..255 bytes, got {len(data)}")
    apdu = bytes([0x80, ins, 0x00, 0x00, len(data)]) + bytes(data) + b"\x00"
    return _transmit(conn, apdu)


# AIDs installed by this repo, plus one that exists nowhere.
PROBES = [
    ("card manager (ISD)", "A000000151000000"),
    ("FIDO2Applet", "A0000006472F0001"),
    ("ECC signer", APPLET_AID.hex()),
    ("EMV PSE 1PAY.SYS.DDF01", b"1PAY.SYS.DDF01".hex()),
    ("EMV PPSE 2PAY.SYS.DDF01", b"2PAY.SYS.DDF01".hex()),
    ("EMV payment app", "AFFFFFFFFF1234"),
    ("made-up AID", "A000000001"),
]


def main():
    conn = connect(wait=30)
    found = []
    for name, aid_hex in PROBES:
        aid = bytes.fromhex(aid_hex)
        # CLA 00, INS A4 SELECT, P1 04 by AID, P2 00 first match, Lc, AID, Le 00
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + b"\x00"
        data, sw = _transmit(conn, apdu)
        print(f"SELECT {name}")
        print(f"  >> {apdu.hex(' ').upper()}")
        print(f"  << {(data.hex(' ').upper() + ' ') if data else ''}{sw:04X}")
        if sw == SW_OK:
            found.append((name, aid_hex.upper()))

    print("\ninstalled:")
    for name, aid in found:
        print(f"  {aid}  {name}")


if __name__ == "__main__":
    main()
