# JavaCard payment card + FIDO2/U2F token

One NXP JCOP card (J3R180, SCP03, default ISD keys) carrying two applications:

| Application | Source               | AIDs                                                    |
| ----------- | -------------------- | ------------------------------------------------------- |
| EMV payment | [emv-card-sim][emv]  | `AFFFFFFFFF1234` (payment app), `1PAY.SYS.DDF01` (PSE), |
|             |                      | `2PAY.SYS.DDF01` (PPSE)                                 |
| FIDO2 / U2F | [FIDO2Applet][fido2] | `A0000006472F0001`                                      |

[fido2]: https://github.com/BryanJacobs/FIDO2Applet
[emv]: https://github.com/mrautio/emv-card-simulator

A terminal or `src/emv/read-payment-card.py` finds the payment app through the
PSE (chip) or PPSE (NFC). A FIDO client selects `A0000006472F0001` directly. The
card routes each command by AID, so the two never interact.

The EMV app is a test card: test keys, test PAN `1234560012345608`, no issuer
behind it. It answers a full EMV flow (including GENERATE AC and DDA (Dynamic
Data Authentication)), but no bank will approve its cryptograms.

## Prerequisites

```sh
curl -LO https://github.com/martinpaljak/ant-javacard/releases/latest/download/ant-javacard.jar
```

`build.xml` loads `ant-javacard.jar` from the repo root.

```sh
brew install ant martinpaljak/brew/gppro
git submodule update --init --recursive   # sdks/, fido2applet/, emv-card-simulator/
uv sync
```

Reader: any PC/SC reader. The commands below use the Feitian R502 contactless
interface:

```sh
export GP_READER="Feitian R502 Contactless Reader"
```

## Free the card

A J3R180 has room for FIDO2Applet plus the EMV app, but likely nothing else.
Delete every package except the card manager's `A0000001515350` and, if it is
already installed, FIDO2Applet's `A000000647`:

```sh
gp --list                                 # see what is installed
gp --delete <package AID> -f              # removes the package and its instances
```

Deleting `A000000647` destroys FIDO2Applet's keys. Every credential registered
with a website stops working, and the PIN goes back to unset.

Any applet already holding `1PAY.SYS.DDF01` or `2PAY.SYS.DDF01` must go too, or
creating the PSE/PPSE instances fails.

After this, `gp --list` shows the ISD `A000000151000000`, PKG `A0000001515350`,
and `A000000647` if you kept FIDO2Applet.

## Run the ECC-sign demo applet

The smallest applet here: one injected P-256 key, the card signs host
challenges. Package `F0DEC0DE01`, instance `F0DEC0DE0101`.

```sh
ant signer                                # → build/signer.cap
gp --install build/signer.cap             # loads F0DEC0DE01, creates F0DEC0DE0101
uv run python src/signer/provision.py     # pushes the key, writes card_pub.pem
uv run python src/signer/verify.py [hex]  # card signs, host verifies
```

`provision.py` works once per instance: the card answers `6985` if a key is
already set. Whoever provisions first owns the key, so do it right after
install. Only the public key is kept on the host, in `card_pub.pem`
(gitignored). The scripts pick the reader from `GP_READER`.

If `provision.py` fails with `SELECT f0dec0de0101 failed: SW=6A82`, the instance
is missing. Check with `gp --list`: if `PKG: F0DEC0DE01` is listed but
`APP: F0DEC0DE0101` is not, create the instance:

```sh
gp --create F0DEC0DE0101 --package F0DEC0DE01 --applet F0DEC0DE0101
```

If neither is listed, run `gp --install build/signer.cap`.

Remove it before installing the other applications if space is tight:

```sh
gp --delete F0DEC0DE01 -f                 # destroys the key
```

## Install the EMV application

- [emv-card-simulator](https://github.com/mrautio/emv-card-simulator)

```sh
ant emv-sim                               # → build/emvsim.cap
gp --load build/emvsim.cap
gp --create AFFFFFFFFF1234               --package AFFFFFFFFF0000 --applet AFFFFFFFFF1234
gp --create 325041592E5359532E4444463031 --package AFFFFFFFFF0000 --applet AFFFFFFFFF0002
gp --create 315041592E5359532E4444463031 --package AFFFFFFFFF0000 --applet AFFFFFFFFF0001
```

The applets start empty. Load the card data (upstream's default profile, a
Visa-like "VESA" card with DDA) with upstream's `cardtool`, built from
`emv-card-simulator/src/main/rust/cardtool` (`cargo build --release`) and copied
to the repo root. It takes one script per run:

```sh
C=emv-card-simulator/src/main/rust/config
./cardtool --load $C/card_setup_pse_apdus.yaml    # PSE  1PAY.SYS.DDF01
./cardtool --load $C/card_setup_ppse_apdus.yaml   # PPSE 2PAY.SYS.DDF01
./cardtool --load $C/card_setup_app_apdus.yaml    # payment app AFFFFFFFFF1234
```

`cardtool` has no reader option: it uses the first reader holding a card, so
keep only one card in the R502. It logs every APDU as a hex dump and prints no
summary; exit status 0 means every status word matched, a mismatch panics.

Each script starts with a factory reset of its applet, so re-running it replaces
the data. Other profiles are in `emv-card-simulator/src/test/java/config/` (e.g.
Visa and Mastercard contactless).

## Check the application

```sh
uv run src/emv/read-payment-card.py                 # EMV: SELECT, GPO, READ RECORD
```

## Remove the EMV application

```sh
gp --delete AFFFFFFFFF0000 -f
```

`-f` deletes the package and its three instances in one command. Deleting an
instance alone fails with `6985`: the package's static fields still reference
objects the instance created.

## Install FIDO2Applet

- [FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet)

```sh
ant fido2                                 # → build/fido2.cap
gp --install build/fido2.cap              # loads A000000647, creates A0000006472F0001
gp --list                                 # APP A0000006472F0001 (SELECTABLE)
```

This uses the default install parameters, which are the FIDO-compliant ones.

The applet starts with no PIN. iPhone and most websites require one, so set it
once:

```sh
GP_READER="Contactless Reader" uv run python src/fido2/set_pin.py --pin 123456
```

Change it later with `--old 123456 --pin <new>`. Then check the applet works:

```sh
GP_READER="Contactless Reader" uv run python src/fido2/demo.py
```

`demo.py` registers and authenticates a test credential, verifies both
signatures, and deletes the test credential. A clean run means the applet works.
With `--verbose` (`-v`), every CTAP2 command and reply on the wire is printed
decoded under its step (ClientPIN key agreement and PIN token, makeCredential
with parsed authData, getAssertion, credential management), via
`src/fido2/ctap_trace.py`. After that, register the card on a website from the
iPhone Safari app: Security Key → NFC → hold the card to the top of the phone →
enter the PIN.

## Why the build differs from upstream

- **One package, not three.** Upstream's Gradle build loads the same package
  three times, once per applet, because the converter requires every applet AID
  to share the package's RID (first 5 bytes). That is ~66 KB; the card returned
  `6A84 Not enough memory`. `ant emv-sim` builds one ~22 KB package with all
  three classes under RID `AFFFFFFFFF`, and the PSE/PPSE instances get their
  standard AIDs at `--create` time. The sources expect this: statics are shared
  across the package's applets, "only one of them is selected at a time".
- **Ant, not Gradle.** Upstream targets Java 1.7 class files, which current JDKs
  cannot produce. The repo's Ant setup (converter from `sdks/jc320v26.0_kit`,
  `targetsdk 3.0.5`) builds the same sources.

## macOS notes

- The macOS CCID driver can connect a chip card with T=1 even when its ATR
  allows only T=0; every command then fails with `Transaction failed`.
  `read-payment-card.py` reconnects such cards with T=0. JCOP cards support T=1,
  so `cardtool` is unaffected.
- Some bank cards (seen: a Visa with ATR `3B FB 13 00 FF 10 80 …`) return no
  bytes at all in the R502 chip slot; read them over NFC.

---

## Resources

- [Getting started with GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Getting-started)

- [JavaCard Buyer's Guide](https://github.com/martinpaljak/GlobalPlatformPro/wiki/JavaCard-Buyer%27s-Guide)

- [FIDO2 & CTAP Protocol: How Hardware Security Keys Work](https://www.cupass.com/en/learn/fido2-ctap-guide.html)

- [PC/SC & CCID: Smart Card Reader Programming Guide](https://www.cupass.com/en/learn/pcsc-programming.html)
