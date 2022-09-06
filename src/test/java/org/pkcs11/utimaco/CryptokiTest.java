/*
 * Copyright 2022 - based on existing tests in CriptokiTest.java. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.pkcs11.utimaco;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.pkcs11.jacknji11.CE;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

import junit.framework.TestCase;

/**
 * JUnit tests for jacknji11.
 * Test Edward curves in Utimaco HSM (Cryptoserver v. 4.31)
 * 
 * Based on existing tests in CriptokiTest.java
 */
public class CryptokiTest extends TestCase {
    private byte[] SO_PIN = "sopin".getBytes();
    private byte[] USER_PIN = "userpin".getBytes();
    private long TESTSLOT = 0;
    private long INITSLOT = 1;

    public void setUp() {
        String testSlotEnv = System.getenv("JACKNJI11_TEST_TESTSLOT");
        if (testSlotEnv != null && testSlotEnv.length() > 0) {
            TESTSLOT = Long.parseLong(testSlotEnv);
        }
        String initSlotEnv = System.getenv("JACKNJI11_TEST_INITSLOT");
        if (initSlotEnv != null && initSlotEnv.length() > 0) {
            INITSLOT = Long.parseLong(initSlotEnv);
        }
        String soPinEnv = System.getenv("JACKNJI11_TEST_SO_PIN");
        if (soPinEnv != null && soPinEnv.length() > 0) {
            SO_PIN = soPinEnv.getBytes();
        }
        String userPinEnv = System.getenv("JACKNJI11_TEST_USER_PIN");
        if (userPinEnv != null && userPinEnv.length() > 0) {
            USER_PIN = userPinEnv.getBytes();
        }
        // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such
        // as:
        // C.NATIVE = new
        // org.pkcs11.jacknji11.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new org.pkcs11.jacknji11.jffi.JFFI();
        CE.Initialize();
    }

    public void tearDown() {
        CE.Finalize();
    }

    public void testSignVerifyEd25519() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION,
                null, null);
        CE.LoginUser(session, USER_PIN);

        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms
        // Specification Version 2.40 section 2.3.3 - ECDSA public key objects
        /*
         * DER-encoding of an ANSI X9.62 Parameters, also known as
         * "EC domain parameters".
         */
        // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570
        // In Utimaco, EC_PARAMS needs to have the value "edwards25519"

        CKA[] pubTempl = new CKA[] {
                new CKA(CKA.EC_PARAMS, "edwards25519"),
                new CKA(CKA.WRAP, false),
                new CKA(CKA.ENCRYPT, false),
                new CKA(CKA.VERIFY, true),
                new CKA(CKA.VERIFY_RECOVER, false),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.LABEL, "labelec-public"),
                new CKA(CKA.ID, "labelec"),
        };
        CKA[] privTempl = new CKA[] {
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.SIGN, true),
                new CKA(CKA.SIGN_RECOVER, false),
                new CKA(CKA.DECRYPT, false),
                new CKA(CKA.UNWRAP, false),
                new CKA(CKA.EXTRACTABLE, false),
                new CKA(CKA.LABEL, "labelec-private"),
                new CKA(CKA.ID, "labelec"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        System.out.println("testSignVerifyEd25519: edwards25519 keypair generated. PublicKey handle: " + pubKey.value()
                + ", PrivKey handle: " + privKey.value());

        // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
        byte[] data = new byte[32]; // SHA256 hash is 32 bytes
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);

        System.out.println(
                "testSignVerifyEd25519: Signature generated with length == 64? " + String.valueOf(64 == sig1.length));

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        CE.Verify(session, data, sig1);

        System.out.println("testSignVerifyEd25519: Signature verified");

        byte[] data1 = new byte[256]; // SHA256 hash is 32 bytes
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig2 = CE.Sign(session, data1);

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        try {
            CE.Verify(session, data, sig2);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            System.out.println(
                    "testSignVerifyEd25519: Verifying invalid signature. Exception expected " + CKR.SIGNATURE_INVALID
                            + " : "
                            + CKR.L2S(CKR.SIGNATURE_INVALID) + " - Actual exception: "
                            + e.getCKR() + " : " + CKR.L2S(e.getCKR()));
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID,
                    e.getCKR());
        }
    }

}
