"""Print metadata of an EMV payment card, read over the chip slot or NFC.

Usage: uv run src/emv/read-payment-card.py

The script selects the payment application, starts a transaction (GPO) and
reads the records the card lists. It does not ask the card to sign anything
and sends nothing to a bank. GPO does advance the card's transaction counter.
"""

import datetime
import os
import sys

from smartcard.ATR import ATR
from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.System import readers
from smartcard.util import toHexString

# Tried in this order when the card has no application list (PSE/PPSE).
KNOWN_AIDS = [
    "A0000000031010",  # Visa
    "A0000000032010",  # Visa Electron
    "A0000000041010",  # Mastercard
    "A0000000043060",  # Maestro
    "A00000002501",  # American Express
    "A0000000651010",  # JCB
    "A0000001523010",  # Discover
]

# Terminal data the card can ask for before GPO (PDOL). Unlisted tags are sent as zeros.
TERMINAL = {
    0x9F66: bytes.fromhex("7EC00000"),  # terminal abilities (TTQ)
    0x9F02: bytes.fromhex("000000000100"),  # amount: 1.00
    0x9F1A: bytes.fromhex("0616"),  # terminal country: Poland
    0x5F2A: bytes.fromhex("0985"),  # currency: PLN
    0x9F35: bytes.fromhex("22"),  # terminal type
    0x9F33: bytes.fromhex("E0F8C8"),  # terminal capabilities
}

COUNTRIES = {"0616": "Poland", "0428": "Latvia", "0276": "Germany", "0826": "United Kingdom",
             "0840": "USA", "0804": "Ukraine", "0250": "France", "0528": "Netherlands"}
CURRENCIES = {"0985": "PLN", "0978": "EUR", "0840": "USD", "0826": "GBP", "0980": "UAH"}

CVM_METHODS = {0x00: "fail", 0x01: "offline PIN", 0x02: "online PIN",
               0x03: "offline PIN + signature", 0x04: "offline PIN (encrypted)",
               0x05: "offline PIN (encrypted) + signature", 0x1E: "signature", 0x1F: "no check"}
CVM_CONDITIONS = {0x00: "always", 0x01: "at unattended cash", 0x02: "if not cash",
                  0x03: "if the terminal supports it", 0x04: "at manual cash",
                  0x05: "at purchase with cashback"}


class NotPaymentCard(Exception):
    pass


def parse_tlv(data):
    """BER-TLV -> list of (tag, value, children); children is None for plain values."""
    items, i = [], 0
    while i < len(data):
        if data[i] in (0x00, 0xFF):  # padding
            i += 1
            continue
        start = i
        i += 1
        if data[start] & 0x1F == 0x1F:  # multi-byte tag
            while data[i] & 0x80:
                i += 1
            i += 1
        tag = int.from_bytes(data[start:i], "big")
        length = data[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        value = bytes(data[i:i + length])
        i += length
        children = parse_tlv(value) if data[start] & 0x20 else None
        items.append((tag, value, children))
    return items


def flatten(items, out):
    """Collect every plain tag into `out` (first value wins) and every 61 template into out[0x61]."""
    for tag, value, children in items:
        if children is None:
            out.setdefault(tag, value)
        else:
            if tag == 0x61:
                out.setdefault(0x61, []).append(children)
            flatten(children, out)
    return out


def parse_dol(dol):
    """Data object list: (tag, length) pairs, no values."""
    entries, i = [], 0
    while i < len(dol):
        start = i
        i += 1
        if dol[start] & 0x1F == 0x1F:
            while dol[i] & 0x80:
                i += 1
            i += 1
        entries.append((int.from_bytes(dol[start:i], "big"), dol[i]))
        i += 1
    return entries


def fill_pdol(pdol):
    dynamic = {0x9A: bytes.fromhex(datetime.date.today().strftime("%y%m%d")),
               0x9F37: os.urandom(4)}  # date, random number
    return b"".join(dynamic.get(tag, TERMINAL.get(tag, b""))[:n].rjust(n, b"\x00")
                    for tag, n in parse_dol(pdol))


TAG_NAMES = {
    0x4F: "Application ID (AID)", 0x50: "Application label", 0x57: "Track 2 data",
    0x5A: "Card number (PAN)", 0x5F20: "Cardholder name", 0x5F24: "Expiry date",
    0x5F25: "Valid from", 0x5F28: "Issuer country", 0x5F2D: "Languages",
    0x5F34: "Card sequence number", 0x61: "Application entry", 0x6F: "Application details (FCI)",
    0x70: "Record", 0x77: "GPO reply", 0x80: "GPO reply (short form)",
    0x82: "What the card supports (AIP)", 0x84: "Selected name", 0x87: "Priority",
    0x88: "File with the application list", 0x8C: "Data the card needs to sign (CDOL1)",
    0x8D: "Data for a second signature (CDOL2)", 0x8E: "Cardholder checks (CVM list)",
    0x8F: "Scheme key index", 0x90: "Issuer certificate", 0x92: "Issuer key remainder",
    0x93: "Signed card data", 0x94: "Records to read (AFL)", 0x9F07: "Usage restrictions",
    0x9F08: "Application version", 0x9F0D: "Issuer rule: default", 0x9F0E: "Issuer rule: decline",
    0x9F0F: "Issuer rule: go online", 0x9F10: "Issuer data", 0x9F11: "Character set",
    0x9F12: "Application name", 0x9F1F: "Track 1 extra data",
    0x9F26: "Cryptogram (the card's signature)", 0x9F27: "Cryptogram type",
    0x9F32: "Issuer key exponent", 0x9F36: "Transaction counter",
    0x9F38: "Data the card needs to start (PDOL)", 0x9F42: "Card currency",
    0x9F46: "Card certificate", 0x9F47: "Card key exponent", 0x9F48: "Card key remainder",
    0x9F49: "Data for offline signing (DDOL)", 0x9F4A: "Signed tag list",
    0x9F4D: "Transaction log location", 0x9F6C: "Contactless rules (CTQ)", 0x9F6E: "Form factor",
    0xA5: "Proprietary details", 0xBF0C: "Issuer details",
    # Terminal data that a card can ask for:
    0x95: "Terminal check results", 0x9A: "Date", 0x9C: "Transaction type", 0x9F02: "Amount",
    0x9F03: "Other amount (cashback)", 0x9F1A: "Terminal country", 0x5F2A: "Currency",
    0x9F37: "Random number", 0x9F66: "Terminal abilities (TTQ)", 0x9F35: "Terminal type",
    0x9F33: "Terminal capabilities",
}


def describe(tag, value):
    """Meaning of a value in words, or None if only the hex is useful."""
    h = value.hex().upper()
    if tag in (0x50, 0x9F12, 0x5F20, 0x5F2D) or (tag == 0x84 and value.endswith(b"DDF01")):
        return f'"{text(value)}"'
    if tag == 0x5A:
        return h.rstrip("F")
    if tag in (0x5F24, 0x5F25, 0x9A):
        return date(value)
    if tag == 0x57:
        number, _, rest = h.partition("D")
        return f"card {number}, expires 20{rest[0:2]}-{rest[2:4]}, service code {rest[4:7]}"
    if tag in (0x5F28, 0x9F1A):
        return COUNTRIES.get(h, f"country code {h}")
    if tag in (0x9F42, 0x5F2A):
        return CURRENCIES.get(h, f"currency code {h}")
    if tag in (0x9F02, 0x9F03):
        return f"{int(h) / 100:.2f}"
    if tag == 0x9F36:
        return f"{int(h, 16)} transactions so far"
    if tag == 0x9F27:
        kinds = {0x00: "AAC: the card declines", 0x40: "TC: the card approves offline",
                 0x80: "ARQC: the card asks the bank to approve"}
        return kinds.get(value[0] & 0xC0)
    if tag == 0x82:
        return "offline authentication: " + offline_auth(value)
    if tag == 0x94:
        return "; ".join(f"file {value[i] >> 3}, records {value[i + 1]}-{value[i + 2]}"
                         for i in range(0, len(value) - 3, 4))
    if tag in (0x9F38, 0x8C, 0x8D, 0x9F49):
        return ", ".join(f"{TAG_NAMES.get(t, f'tag {t:X}')} ({n} B)" for t, n in parse_dol(value))
    if tag == 0x8E:
        return "; ".join(cvm_list(value))
    if tag == 0x9C:
        return {"00": "purchase", "01": "cash", "20": "refund"}.get(h)
    if tag == 0x9F37:
        return "new for every transaction"
    return None


def show_tlv(items, indent=2):
    pad = "  " * indent
    for tag, value, children in items:
        name = TAG_NAMES.get(tag, "unknown tag")
        if children is not None:
            print(f"{pad}{tag:X} {name}:")
            show_tlv(children, indent + 1)
            continue
        meaning = describe(tag, value)
        hexval = value.hex().upper()
        if len(hexval) > 40:
            hexval = f"{hexval[:40]}... ({len(value)} bytes)"
        print(f"{pad}{tag:X} {name}: {meaning or hexval}")


class Card:
    def __init__(self, connection):
        self.connection = connection
        # macOS can pick T=1 for a chip card whose ATR allows only T=0; every command then fails.
        if not ATR(connection.getATR()).isT1Supported():
            connection.disconnect()
            connection.connect(CardConnection.T0_protocol)
        self.t0 = connection.getProtocol() == CardConnection.T0_protocol

    def exchange(self, apdu):
        """Transmit one APDU; print the raw bytes both ways."""
        reply, sw1, sw2 = self.connection.transmit(apdu)
        sw = (sw1 << 8) | sw2
        print(f"  >> {toHexString(apdu)}")
        print(f"  << {toHexString(reply) + '  ' if reply else ''}{sw:04X}: {status(sw)}")
        return reply, sw1, sw2

    def send(self, name, purpose, apdu, data=b"", sent=None):
        """Send a command, print what it does and the decoded reply; return (status, reply)."""
        print(f"== {name}")
        print(f"  {purpose}")
        for line in sent or []:
            print(f"  sends {line}")
        if data:
            apdu = apdu + [len(data)] + list(data)
            if not self.t0:
                apdu.append(0x00)  # Le: without it the card sends no reply data
        else:
            apdu = apdu + [0x00]
        reply, sw1, sw2 = self.exchange(apdu)
        if sw1 == 0x6C:
            print("  The card asked for a different reply length. Sending the command again:")
            reply, sw1, sw2 = self.exchange(apdu[:-1] + [sw2])
        while sw1 == 0x61:
            print("  The reply is waiting on the card. Fetching it with GET RESPONSE:")
            more, sw1, sw2 = self.exchange([0x00, 0xC0, 0x00, 0x00, sw2])
            reply += more
        sw = (sw1 << 8) | sw2
        if sw == 0x9000 and reply:
            print("  Reply:")
            show_tlv(parse_tlv(bytes(reply)))
        print()
        return sw, bytes(reply)

    def select(self, name, purpose):
        shown = name.decode() if name.endswith(b"DDF01") else name.hex().upper()
        sw, reply = self.send(f"SELECT {shown}", purpose, [0x00, 0xA4, 0x04, 0x00], name)
        return parse_tlv(reply) if sw == 0x9000 else None

    def read_record(self, sfi, record, purpose):
        sw, reply = self.send(f"READ RECORD file {sfi}, record {record}", purpose,
                              [0x00, 0xB2, record, (sfi << 3) | 4])
        return parse_tlv(reply) if sw == 0x9000 else None


STATUS = {0x9000: "OK",
          0x6700: "wrong length: the card expects different data",
          0x6985: "refused: an earlier step is missing",
          0x6A81: "function not supported",
          0x6A82: "not found: the card has no such application or record",
          0x6A83: "record not found",
          0x6A86: "wrong parameters",
          0x6D00: "command not supported (no application is selected)",
          0x6E00: "command class not supported"}


def status(sw):
    if sw >> 8 == 0x61:
        return f"{sw & 0xFF} more bytes waiting"
    if sw >> 8 == 0x6C:
        return f"wrong length, the card wants {sw & 0xFF} bytes"
    return STATUS.get(sw, "error")


def find_applications(card, contactless):
    """AIDs listed by the card's PPSE (NFC) or PSE (chip), highest priority first."""
    if contactless:
        fci = card.select(b"2PAY.SYS.DDF01", "Ask the card which payment applications it has "
                          "(the contactless directory, PPSE).")
    else:
        fci = card.select(b"1PAY.SYS.DDF01", "Ask the card which payment applications it has "
                          "(the chip directory, PSE).")
    if fci is None:
        print("The card has no directory. Trying the common payment applications one by one.\n")
        return [bytes.fromhex(aid) for aid in KNOWN_AIDS]
    tags = flatten(fci, {})
    if 0x88 in tags:  # chip PSE: the list is in directory records
        for record in range(1, 17):
            items = card.read_record(tags[0x88][0], record,
                                     "Read the next entry of the application directory.")
            if items is None:
                break
            flatten(items, tags)
    apps = []
    for app in tags.get(0x61, []):
        entry = flatten(app, {})
        if 0x4F in entry:
            priority = entry.get(0x87, b"\x0f")[0] & 0x0F
            apps.append((priority, entry[0x4F]))
    return [aid for _, aid in sorted(apps)] or [bytes.fromhex(aid) for aid in KNOWN_AIDS]


def read_card(card, contactless):
    for aid in find_applications(card, contactless):
        fci = card.select(aid, "Open this payment application. The card replies with its name "
                          "and the terminal data it needs to start a transaction (PDOL).")
        if fci is not None:
            break
    else:
        raise NotPaymentCard("no payment application found")
    tags = flatten(fci, {0x4F: aid})

    pdol = parse_dol(tags.get(0x9F38, b""))
    terminal_data = fill_pdol(tags.get(0x9F38, b""))
    sent, offset = [], 0
    for tag, n in pdol:
        value = terminal_data[offset:offset + n]
        offset += n
        meaning = describe(tag, value)
        sent.append(f"{TAG_NAMES.get(tag, f'tag {tag:X}')}: {value.hex().upper()}"
                    + (f" ({meaning})" if meaning else ""))
    sw, reply = card.send(
        "GET PROCESSING OPTIONS",
        "Start a transaction, giving the card the terminal data it asked for. The card replies "
        "with what it supports (AIP) and which records hold its data (AFL). Contactless Visa "
        "cards also return the transaction signature (cryptogram) here.",
        [0x80, 0xA8, 0x00, 0x00], bytes([0x83, len(terminal_data)]) + terminal_data,
        sent or ["no data: the card asked for none"])
    if sw != 0x9000:
        print(f"Card refused GET PROCESSING OPTIONS ({sw:04X}); showing data from SELECT only.\n")
        return tags
    gpo = parse_tlv(reply)
    if gpo and gpo[0][0] == 0x80:  # short form: AIP (2 bytes) + AFL
        tags[0x82], tags[0x94] = gpo[0][1][:2], gpo[0][1][2:]
    else:
        flatten(gpo, tags)

    afl = tags.get(0x94, b"")
    for i in range(0, len(afl) - 3, 4):
        for record in range(afl[i + 1], afl[i + 2] + 1):
            items = card.read_record(afl[i] >> 3, record,
                                     "Read one of the records that GPO listed. Records hold the "
                                     "card number, dates, cardholder checks and certificates.")
            if items is not None:
                flatten(items, tags)
    return tags


def text(value):
    return value.decode("ascii", "replace").strip()


def date(value):
    h = value.hex()
    return f"20{h[0:2]}-{h[2:4]}" + (f"-{h[4:6]}" if len(h) >= 6 else "")


def cvm_list(value):
    rules = []
    for i in range(8, len(value) - 1, 2):  # first 8 bytes are amount limits
        method = CVM_METHODS.get(value[i] & 0x3F, f"method {value[i] & 0x3F:02X}")
        condition = CVM_CONDITIONS.get(value[i + 1], f"condition {value[i + 1]:02X}")
        rules.append(f"{method} ({condition})")
    return rules


def offline_auth(aip):
    kinds = [(0x40, "static (SDA)"), (0x20, "dynamic (DDA)"), (0x01, "combined (CDA)")]
    return ", ".join(name for bit, name in kinds if aip[0] & bit) or "none (online only)"


def print_metadata(tags):
    pan, expiry = tags.get(0x5A), tags.get(0x5F24)
    if 0x57 in tags:  # track 2: PAN 'D' YYMM service-code ...
        number, _, rest = tags[0x57].hex().upper().partition("D")
        pan = pan or bytes.fromhex(number.ljust(len(number) + len(number) % 2, "F"))
        expiry = expiry or bytes.fromhex(rest[:4])
        service_code = rest[4:7]
    else:
        service_code = None

    rows = [
        ("Application", text(tags.get(0x9F12) or tags.get(0x50) or b"")),
        ("AID", tags[0x4F].hex().upper()),
        ("Card number", pan.hex().upper().rstrip("F") if pan else None),
        ("Cardholder name", text(tags[0x5F20]) if 0x5F20 in tags else None),
        ("Valid from", date(tags[0x5F25]) if 0x5F25 in tags else None),
        ("Expires", date(expiry) if expiry else None),
        ("Card sequence number", tags[0x5F34].hex() if 0x5F34 in tags else None),
        ("Service code", service_code),
        ("Issuer country", COUNTRIES.get(tags[0x5F28].hex(), tags[0x5F28].hex())
         if 0x5F28 in tags else None),
        ("Card currency", CURRENCIES.get(tags[0x9F42].hex(), tags[0x9F42].hex())
         if 0x9F42 in tags else None),
        ("Languages", text(tags[0x5F2D]) if 0x5F2D in tags else None),
        ("Offline authentication", offline_auth(tags[0x82]) if 0x82 in tags else None),
        ("Transactions so far", int.from_bytes(tags[0x9F36], "big") if 0x9F36 in tags else None),
    ]
    for label, value in rows:
        if value:
            print(f"{label + ':':24}{value}")
    if 0x8E in tags:
        print("Cardholder checks:")
        for n, rule in enumerate(cvm_list(tags[0x8E]), 1):
            print(f"  {n}. {rule}")


def main():
    slots = [r for r in readers() if str(r).endswith(("Contact Reader", "Contactless Reader"))]
    if not slots:
        print("No contact or contactless reader found.")
        return 2
    try:
        service = CardRequest(timeout=10, readers=slots).waitforcard()
    except CardRequestTimeoutException:
        print("No card found. Insert the card or place it on the reader.")
        return 2
    assert service is not None  # waitforcard raises on timeout instead
    service.connection.connect()
    reader = str(service.connection.getReader())
    contactless = "Contactless" in reader
    print(f"Reader: {reader}")
    print(f"ATR:    {toHexString(service.connection.getATR())}\n")
    try:
        tags = read_card(Card(service.connection), contactless)
        print("== Summary")
        print_metadata(tags)
    except (NotPaymentCard, CardConnectionException) as e:
        print(f"Not a readable payment card: {e}")
        return 1
    finally:
        service.connection.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
