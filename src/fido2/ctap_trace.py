"""Print every CTAP2 command sent to the authenticator and its reply.

`TracingDevice` wraps a `CtapDevice` and decodes the CBOR on the wire, so it
also shows the exchanges `Fido2Client` makes on its own (ClientPIN key
agreement, PIN token). Field names follow the CTAP 2.1 specification.
"""

# pyright: reportAny=false, reportExplicitAny=false

import os
import sys
from collections.abc import Callable, Iterator, Mapping
from threading import Event
from typing import Any, cast, override

from fido2.client import DefaultClientDataCollector
from fido2.ctap import STATUS, CtapDevice, CtapError
from fido2.hid import CTAPHID
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)

from fido2 import cbor

# Bold, colored party labels, also used by demo.py: relying party blue, client
# purple, authenticator green. Plain text when stdout is not a terminal or
# NO_COLOR is set.
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _sgr(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(text: str) -> str:
    return _sgr("1", text)


def rp(text: str) -> str:
    return _sgr("1;34", text)


def client(text: str) -> str:
    return _sgr("1;35", text)


def card(text: str) -> str:
    return _sgr("1;32", text)


ASSERTION_RESPONSE = {
    1: "credential",
    2: "authData",
    3: "signature",
    4: "user",
    5: "numberOfCredentials",
    6: "userSelected",
    7: "largeBlobKey",
}

COMMANDS: dict[int, tuple[str, dict[int, str], dict[int, str]]] = {
    0x01: (
        "authenticatorMakeCredential",
        {
            1: "clientDataHash",
            2: "rp",
            3: "user",
            4: "pubKeyCredParams",
            5: "excludeList",
            6: "extensions",
            7: "options",
            8: "pinUvAuthParam",
            9: "pinUvAuthProtocol",
            10: "enterpriseAttestation",
        },
        {1: "fmt", 2: "authData", 3: "attStmt", 4: "epAtt", 5: "largeBlobKey"},
    ),
    0x02: (
        "authenticatorGetAssertion",
        {
            1: "rpId",
            2: "clientDataHash",
            3: "allowList",
            4: "extensions",
            5: "options",
            6: "pinUvAuthParam",
            7: "pinUvAuthProtocol",
        },
        ASSERTION_RESPONSE,
    ),
    0x04: (
        "authenticatorGetInfo",
        {},
        {
            1: "versions",
            2: "extensions",
            3: "aaguid",
            4: "options",
            5: "maxMsgSize",
            6: "pinUvAuthProtocols",
            7: "maxCredentialCountInList",
            8: "maxCredentialIdLength",
            9: "transports",
            10: "algorithms",
            11: "maxSerializedLargeBlobArray",
            12: "forcePINChange",
            13: "minPINLength",
            14: "firmwareVersion",
            15: "maxCredBlobLength",
            16: "maxRPIDsForSetMinPINLength",
            17: "preferredPlatformUvAttempts",
            18: "uvModality",
            19: "certifications",
            20: "remainingDiscoverableCredentials",
        },
    ),
    0x08: ("authenticatorGetNextAssertion", {}, ASSERTION_RESPONSE),
    0x06: (
        "authenticatorClientPIN",
        {
            1: "pinUvAuthProtocol",
            2: "subCommand",
            3: "keyAgreement",
            4: "pinUvAuthParam",
            5: "newPinEnc",
            6: "pinHashEnc",
            9: "permissions",
            10: "rpId",
        },
        {
            1: "keyAgreement",
            2: "pinUvAuthToken",
            3: "pinRetries",
            4: "powerCycleState",
            5: "uvRetries",
        },
    ),
    0x0A: (
        "authenticatorCredentialManagement",
        {
            1: "subCommand",
            2: "subCommandParams",
            3: "pinUvAuthProtocol",
            4: "pinUvAuthParam",
        },
        {
            1: "existingResidentCredentialsCount",
            2: "maxPossibleRemainingResidentCredentialsCount",
            3: "rp",
            4: "rpIDHash",
            5: "totalRPs",
            6: "user",
            7: "credentialID",
            8: "publicKey",
            9: "totalCredentials",
            10: "credProtect",
            11: "largeBlobKey",
        },
    ),
}

SUBCOMMANDS: dict[int, dict[int, str]] = {
    0x06: {
        1: "getPINRetries",
        2: "getKeyAgreement",
        3: "setPIN",
        4: "changePIN",
        5: "getPinToken",
        6: "getPinUvAuthTokenUsingUvWithPermissions",
        7: "getUVRetries",
        9: "getPinUvAuthTokenUsingPinWithPermissions",
    },
    0x0A: {
        1: "getCredsMetadata",
        2: "enumerateRPsBegin",
        3: "enumerateRPsGetNextRP",
        4: "enumerateCredentialsBegin",
        5: "enumerateCredentialsGetNextCredential",
        6: "deleteCredential",
        7: "updateUserInformation",
    },
}

# COSE_Key labels (RFC 9052/9053) as used for EC2 public keys.
COSE = {1: "kty", 3: "alg", -1: "crv", -2: "x", -3: "y"}

# authenticatorCredentialManagement subCommandParams keys.
CREDMGMT_PARAMS = {1: "rpIDHash", 2: "credentialID", 3: "user"}

# What coded values mean, keyed by field name.
MEANINGS: dict[str, dict[Any, str]] = {
    "kty": {1: "OKP", 2: "EC2", 3: "RSA"},
    "crv": {1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519"},
    "alg": {
        -7: "ES256",
        -8: "EdDSA",
        -25: "ECDH-ES+HKDF-256",
        -35: "ES384",
        -36: "ES512",
        -37: "PS256",
        -47: "ES256K",
        -48: "ML-DSA-44",
        -49: "ML-DSA-65",
        -50: "ML-DSA-87",
        -257: "RS256",
    },
}

# authenticatorClientPIN permissions bits.
PERMISSIONS = {
    0x01: "makeCredential",
    0x02: "getAssertion",
    0x04: "credentialManagement",
    0x08: "bioEnrollment",
    0x10: "largeBlobWrite",
    0x20: "authenticatorConfig",
}

BYTES_PER_LINE = 32
STEP = "  "
# Maps of plain values with at most this many entries print on one line.
INLINE_MAX = 4


def _note(name: str, value: Any) -> str:
    """Meaning of a coded value, as a trailing "  (…)", or ""."""
    meaning = MEANINGS.get(name, {}).get(value) if isinstance(value, int) else None
    if name == "permissions" and isinstance(value, int):
        meaning = ", ".join(n for bit, n in PERMISSIONS.items() if value & bit)
    return f"  ({meaning})" if meaning else ""


def _scalar(name: str, value: Any) -> str:
    return f"{value!r}{_note(name, value)}"


def _hex(name: str, value: bytes, indent: str) -> list[str]:
    """`name (N bytes): hex`, wrapped with continuation lines aligned to the hex."""
    head = f"{indent}{name} ({len(value)} bytes): "
    hexed = value.hex()
    step = BYTES_PER_LINE * 2
    chunks = [hexed[i : i + step] for i in range(0, len(hexed), step)] or [""]
    pad = " " * len(head)
    return [head + chunks[0]] + [pad + chunk for chunk in chunks[1:]]


def _field(name: str, value: Any, indent: str) -> list[str]:
    """Lines for one field: `name: value`, nested values indented below."""
    if isinstance(value, bytes):
        return _hex(name, value, indent)
    if isinstance(value, Mapping):
        labels: Mapping[Any, str] = COSE if 1 in value and -1 in value else {}
        items = [(str(labels.get(k, k)), v) for k, v in value.items()]
        if len(items) <= INLINE_MAX and not any(
            isinstance(v, (bytes, Mapping, list)) for _, v in items
        ):
            inline = ", ".join(f"{k}: {_scalar(k, v)}" for k, v in items)
            return [f"{indent}{name}: {{{inline}}}"]
        lines = [f"{indent}{name}:"]
        for key, item in items:
            lines += _field(key, item, indent + STEP)
        return lines
    if isinstance(value, list):
        if not any(isinstance(v, (bytes, Mapping, list)) for v in value):
            return [f"{indent}{name}: [{', '.join(repr(v) for v in value)}]"]
        lines = [f"{indent}{name}: {len(value)} item(s)"]
        for i, item in enumerate(value):
            lines += _field(f"[{i}]", item, indent + STEP)
        return lines
    return [f"{indent}{name}: {_scalar(name, value)}"]


def _auth_data(raw: bytes, indent: str) -> list[str]:
    data = AuthenticatorData(raw)
    flags = [f.name for f in AuthenticatorData.FLAG if data.flags & f and f.name]
    inner = indent + STEP
    lines = _hex("authData", raw, indent)
    lines += _hex("rpIdHash", data.rp_id_hash, inner)
    lines.append(f"{inner}flags: 0x{data.flags:02x}  ({', '.join(flags)})")
    lines.append(f"{inner}signCount: {data.counter}")
    cred = data.credential_data
    if cred is not None:
        lines += _hex("aaguid", bytes(cred.aaguid), inner)
        lines += _hex("credentialId", cred.credential_id, inner)
        lines += _field("credentialPublicKey", dict(cred.public_key), inner)
    return lines


def _client_data_hash(
    digest: bytes, known: Mapping[bytes, CollectedClientData], indent: str
) -> list[str]:
    lines = _hex("clientDataHash", digest, indent)
    data = known.get(digest)
    if data is not None:
        inner = indent + STEP
        lines.append(f"{inner}= SHA-256 of clientDataJSON: {data.decode()}")
        lines += _hex("challenge", data.challenge, inner)
    return lines


def _map(encoded: bytes) -> Mapping[int, Any]:
    """CTAP2 payloads are always CBOR maps with integer keys."""
    return cast(Mapping[int, Any], cbor.decode(encoded))


def _fields(
    payload: Mapping[int, Any],
    names: dict[int, str],
    subs: dict[int, str],
    client_data: Mapping[bytes, CollectedClientData],
) -> None:
    indent = "      "
    for key, value in payload.items():
        name = names.get(key, str(key))
        if name == "authData":
            lines = _auth_data(value, indent)
        elif name == "clientDataHash":
            lines = _client_data_hash(value, client_data, indent)
        elif name == "subCommand" and value in subs:
            lines = [f"{indent}{name}: {value}  ({subs[value]})"]
        elif name == "subCommandParams":
            params = {CREDMGMT_PARAMS.get(k, k): v for k, v in value.items()}
            lines = _field(name, params, indent)
        else:
            lines = _field(name, value, indent)
        print("\n".join(lines))


class TracingDevice(CtapDevice):
    """Delegates to `device`; prints decoded CTAP2 traffic while `enabled`."""

    def __init__(self, device: CtapDevice):
        self.device: CtapDevice = device
        self.enabled: bool = False
        # clientDataJSON by its hash, so the trace can show what the card signs.
        self.client_data: dict[bytes, CollectedClientData] = {}

    def client_data_collector(self, origin: str) -> DefaultClientDataCollector:
        """A collector for `origin` that records each clientData for the trace."""
        return _RecordingCollector(origin, self.client_data)

    @property
    @override
    def capabilities(self) -> int:
        return self.device.capabilities

    @override
    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        response = self.device.call(cmd, data, event, on_keepalive)
        if self.enabled and cmd == CTAPHID.CBOR and data:
            self._print(data, response)
        return response

    def _print(self, request: bytes, response: bytes) -> None:
        code = request[0]
        name, req_names, res_names = COMMANDS.get(
            code, (f"command 0x{code:02x}", {}, {})
        )
        subs = SUBCOMMANDS.get(code, {})
        to_card = f"   {client('client')} → {card('authenticator')}:"
        to_client = f"   {card('authenticator')} → {client('client')}:"
        print(f"{to_card} {name}")
        if len(request) > 1:
            _fields(_map(request[1:]), req_names, subs, self.client_data)
        if not response:
            print(f"{to_client} (no response)")
            return
        if response[0] != 0:
            try:
                error = CtapError.ERR(response[0]).name
            except ValueError:
                error = "unknown"
            print(f"{to_client} error 0x{response[0]:02x}  ({error})")
            return
        print(f"{to_client} OK")
        if len(response) > 1:
            _fields(_map(response[1:]), res_names, subs, self.client_data)

    @override
    def close(self) -> None:
        self.device.close()

    @override
    def __repr__(self) -> str:
        return repr(self.device)

    @classmethod
    @override
    def list_devices(cls) -> Iterator[CtapDevice]:
        raise NotImplementedError("wrap an existing device instead")


class _RecordingCollector(DefaultClientDataCollector):
    def __init__(self, origin: str, record: dict[bytes, CollectedClientData]):
        super().__init__(origin)
        self.record: dict[bytes, CollectedClientData] = record

    @override
    def collect_client_data(
        self,
        options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
    ) -> tuple[CollectedClientData, str]:
        data, rp_id = super().collect_client_data(options)
        self.record[data.hash] = data
        return data, rp_id
