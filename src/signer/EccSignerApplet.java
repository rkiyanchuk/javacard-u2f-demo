package signer;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Minimal ECC-signing proof of concept.
 *
 * Holds a single secp256r1 private key that the host injects once, then signs
 * host-supplied challenges with ECDSA-SHA-256. No key generation on card, no
 * install parameters, no FIDO/U2F protocol.
 *
 * <pre>
 * CLA INS Data                      Response            Errors
 * 80  01  32-byte private scalar S  -                   6985 already provisioned, 6700 Lc != 32
 * 80  02  challenge, 1..255 bytes   DER ECDSA signature 6985 not provisioned, 6700 Lc == 0
 * </pre>
 *
 * Provisioning is unauthenticated but one-shot: the first INS 01 locks the key
 * for the lifetime of the applet instance.
 */
public class EccSignerApplet extends Applet {

    private static final byte CLA_DEMO = (byte) 0x80;
    private static final byte INS_PROVISION = (byte) 0x01;
    private static final byte INS_SIGN = (byte) 0x02;

    /** Longest DER ECDSA P-256 signature is 72 bytes. */
    private static final short SCRATCH_LEN = (short) 80;

    private static final short PRIVATE_SCALAR_LEN = (short) 32;

    /* secp256r1 (NIST P-256) domain parameters. The cards' preset curve
     * parameters cannot be relied upon, and JavaCard has no BigInteger, so
     * every value is spelled out. */

    /** Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1. */
    private static final byte[] SECP256R1_P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    };

    /** Coefficient a = p - 3. */
    private static final byte[] SECP256R1_A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC,
    };

    /** Coefficient b. */
    private static final byte[] SECP256R1_B = {
        (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
        (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B,
    };

    /** Base point G, uncompressed: 0x04 || Gx || Gy. */
    private static final byte[] SECP256R1_G = {
        (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42,
        (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
        (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
        (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2,
        (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
        (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
        (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E,
        (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51,
        (byte) 0xF5,
    };

    /** Order n of G. */
    private static final byte[] SECP256R1_N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51,
    };

    /** Cofactor h. */
    private static final short SECP256R1_K = (short) 1;

    private final ECPrivateKey key;
    private final Signature sig;
    private final byte[] scratch;
    private boolean provisioned;

    private EccSignerApplet() {
        key = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                 KeyBuilder.LENGTH_EC_FP_256, false);
        setCurve(key);
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        scratch = JCSystem.makeTransientByteArray(SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    /**
     * Install parameters are deliberately ignored: the key arrives later over
     * INS 01, which keeps the GP install-parameter structure out of the PoC.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EccSignerApplet();
    }

    private static void setCurve(ECKey k) {
        k.setFieldFP(SECP256R1_P, (short) 0, (short) SECP256R1_P.length);
        k.setA(SECP256R1_A, (short) 0, (short) SECP256R1_A.length);
        k.setB(SECP256R1_B, (short) 0, (short) SECP256R1_B.length);
        k.setG(SECP256R1_G, (short) 0, (short) SECP256R1_G.length);
        k.setR(SECP256R1_N, (short) 0, (short) SECP256R1_N.length);
        k.setK(SECP256R1_K);
    }

    private void provision(byte[] buf, short lc) {
        if (provisioned) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (lc != PRIVATE_SCALAR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // setS first, flag second: a tear between the two leaves the applet
        // unprovisioned and therefore still provisionable.
        key.setS(buf, ISO7816.OFFSET_CDATA, lc);
        provisioned = true;
    }

    private void sign(APDU apdu, byte[] buf, short lc) {
        if (!provisioned) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (lc == (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sig.init(key, Signature.MODE_SIGN);
        // Sign into scratch, not in place: overlapping input and output regions
        // are not guaranteed safe in Signature.sign.
        short n = sig.sign(buf, ISO7816.OFFSET_CDATA, lc, scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, buf, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA_DEMO) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short lc = apdu.setIncomingAndReceive(); // Length of command data

        switch (buf[ISO7816.OFFSET_INS]) {
        case INS_PROVISION:
            provision(buf, lc);
            break;
        case INS_SIGN:
            sign(apdu, buf, lc);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
