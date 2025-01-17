/*
 * Copyright 2010-2011 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
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

package org.pkcs11.jacknji11;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import junit.framework.TestCase;

/**
 * JUnit tests for jacknji11.
 * Tests all the cryptoki functions that I have ever used and understand.
 * The functions not tested are in commented lines.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CryptokiTest extends TestCase {
    private static final Log log = LogFactory.getLog(CryptokiTest.class);

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
        // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such as:
        // C.NATIVE = new org.pkcs11.jacknji11.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new org.pkcs11.jacknji11.jffi.JFFI();
        CE.Initialize();
    }

    public void tearDown() {
        CE.Finalize();
    }

    public void testGetInfo() {
        CK_INFO info = new CK_INFO();
        CE.GetInfo(info);
        log.info(String.format("testGetInfo:\n%s", info));
        // System.out.println("testGetInfo");
        // System.out.println(info);
    }

    public void testGetSlotList() {
        long[] slots = CE.GetSlotList(true);
        // System.out.println("testGetSlotList");
        // System.out.println("slots: " + Arrays.toString(slots));
        log.info(String.format("testGetSlotList: slots:\n%s", Arrays.toString(slots)));
    }

    public void testGetSlotInfo() {
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        CE.GetSlotInfo(TESTSLOT, info);
        // System.out.println("testGetSlotInfo - Testslot: " + TESTSLOT);
        // System.out.println(info);
        log.info(String.format("testGetSlotInfo - Testslot info: %d\n%s", TESTSLOT, info));
    }

    public void testGetTokenInfo() {
        CK_TOKEN_INFO info = new CK_TOKEN_INFO();
        CE.GetTokenInfo(TESTSLOT, info);
        // System.out.println("testGetTokenInfo - Testslot: " + TESTSLOT);
        // System.out.println(info);
        log.info(String.format("testGetTokenInfo - Testslot info: %d - Token info\n%s", TESTSLOT, info));
    }

    public void testGetMechanismList() {
        // System.out.println("testGetMechanismList");
        log.info("testGetMechanismList");
        for (long mech : CE.GetMechanismList(TESTSLOT)) {
            log.info(String.format("0x%08x : %s", mech, CKM.L2S(mech)));
        }
    }

    public void testGetMechanismInfo() {
        CK_MECHANISM_INFO info = new CK_MECHANISM_INFO();
        CE.GetMechanismInfo(TESTSLOT, CKM.AES_CBC, info);
        // System.out.println("testGetMechanismInfo");
        // System.out.println(info);
        log.info(String.format("testGetMechanismInfo - Testslot info: %d\n%s", TESTSLOT, info));
    }

    public void testInitTokenInitPinSetPin() {
        CE.InitToken(INITSLOT, SO_PIN, "TEST".getBytes());
        long session = CE.OpenSession(INITSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.SO, SO_PIN);
        CE.InitPIN(session, USER_PIN);
        CE.Logout(session);
        CE.Login(session, CKU.USER, USER_PIN);
        byte[] somenewpin = "somenewpin".getBytes();
        CE.SetPIN(session, USER_PIN, somenewpin);
        CE.SetPIN(session, somenewpin, USER_PIN);
        log.info("testInitTokenInitPinSetPin");
    }

    public void testGetSessionInfo() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CE.GetSessionInfo(session, sessionInfo);
        // System.out.println("testGetSessionInfo");
        // System.out.println(sessionInfo);
        log.info(String.format("testGetSessionInfo:\n%s", sessionInfo));
    }

    public void testGetSessionInfoCloseAllSessions() {
        long s1 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        long s2 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CK_SESSION_INFO info = new CK_SESSION_INFO();
        CE.GetSessionInfo(s2, info );
        // System.out.println("testGetSessionInfoCloseAllSessions");
        // System.out.println(info);
        log.info(String.format("testGetSessionInfoCloseAllSessions:\n%s", info));
        long s3 = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.CloseSession(s1);
        CE.CloseAllSessions(TESTSLOT);
        assertEquals(CKR.SESSION_HANDLE_INVALID, C.CloseSession(s3));
    }

    public void testGetSetOperationState() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        byte[] state = CE.GetOperationState(session);
        CE.SetOperationState(session, state, 0, 0);
        log.info("testGetSetOperationState");
    }

    public void testCreateCopyDestroyObject() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.VALUE, "datavalue"),
        };
        long o1 = CE.CreateObject(session, templ);
        CKA[] newTempl = {
            new CKA(CKA.TOKEN, true),
        };
        long o2 = CE.CopyObject(session, o1, newTempl);
        CE.DestroyObject(session, o1);
        CE.DestroyObject(session, o2);
        log.info("testCreateCopyDestroyObject");
    }

    public void testGetObjectSizeGetSetAtt() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN);
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.PRIVATE, false),
            new CKA(CKA.VALUE, "datavalue"),
        };
        long o = CE.CreateObject(session, templ);
        long size = CE.GetObjectSize(session, o);
        assertNull(CE.GetAttributeValue(session, o, CKA.LABEL).getValueStr());
        assertNull(CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertEquals("datavalue", CE.GetAttributeValue(session, o, CKA.VALUE).getValueStr());
        assertEquals(Long.valueOf(CKO.DATA), CE.GetAttributeValue(session, o, CKA.CLASS).getValueLong());
        assertFalse(CE.GetAttributeValue(session, o, CKA.PRIVATE).getValueBool());
        templ = new CKA[] {
                // Different HSMs are pick in different ways which attributes can be modified, 
                // just modify label which seems to work on most
                new CKA(CKA.LABEL, "datalabel"),
        };
        CE.SetAttributeValue(session, o, templ);
        long newsize = CE.GetObjectSize(session, o);
        if (size > -1) {
            assertTrue("newsize: " + newsize + ", size " + size, newsize > size);
        }
        assertEquals("datalabel", CE.GetAttributeValue(session, o, CKA.LABEL).getValueStr());
        assertNull(CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertEquals("datavalue", CE.GetAttributeValue(session, o, CKA.VALUE).getValueStr());
        assertEquals(Long.valueOf(CKO.DATA), CE.GetAttributeValue(session, o, CKA.CLASS).getValueLong());
        assertFalse(CE.GetAttributeValue(session, o, CKA.PRIVATE).getValueBool());

        templ = CE.GetAttributeValue(session, o, CKA.LABEL, CKA.ID, CKA.VALUE, CKA.CLASS, CKA.PRIVATE);
        assertEquals("datalabel", templ[0].getValueStr());
        assertNull(CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertEquals("datavalue", templ[2].getValueStr());
        assertEquals(CKO.DATA, templ[3].getValueLong().longValue());
        assertFalse(templ[4].getValueBool());

        templ = CE.GetAttributeValue(session, o, CKA.LABEL, CKA.ID, CKA.OBJECT_ID, CKA.TRUSTED);
        assertEquals("datalabel", templ[0].getValueStr());
        assertNull(CE.GetAttributeValue(session, o, CKA.ID).getValueStr());
        assertNull(templ[2].getValue());
        assertNull(templ[3].getValueBool());
        log.info("testGetObjectSizeGetSetAtt");
    }

    public void testFindObjects() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN); // Needed depending on HSM policy
        // create a few objects
        CKA[] templ = {
            new CKA(CKA.CLASS, CKO.DATA),
            new CKA(CKA.LABEL, "label1"),
        };
        long o1 = CE.CreateObject(session, templ);
        long o2 = CE.CreateObject(session, templ);
        long o3 = CE.CreateObject(session, templ);
        assertTrue(o1 != o2);
        templ[1] = new CKA(CKA.LABEL, "label2");
        long o4 = CE.CreateObject(session, templ);

        templ = new CKA[] {new CKA(CKA.LABEL, "label1")};
        CE.FindObjectsInit(session, templ);
        assertEquals(2, CE.FindObjects(session, 2).length);
        assertEquals(1, CE.FindObjects(session, 2).length);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
        templ = new CKA[] {new CKA(CKA.LABEL, "label2")};
        CE.FindObjectsInit(session, templ);
        long[] found = CE.FindObjects(session, 2);
        assertEquals(1, found.length);
        assertEquals(o4, found[0]);
        assertEquals(0, CE.FindObjects(session, 2).length);
        CE.FindObjectsFinal(session);
        log.info("testFindObjects");
    }


    public void testEncryptDecrypt() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);

        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 32),
                new CKA(CKA.LABEL, "labelencaes"),
                new CKA(CKA.ID, "labelencaes"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.ENCRYPT, true),
                new CKA(CKA.DECRYPT, true),
                new CKA(CKA.DERIVE, true));

        CE.EncryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] plaintext = new byte[10];
        byte[] encrypted1 = CE.EncryptPad(session, plaintext);
        CE.EncryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] encrypted2a = CE.EncryptUpdate(session, new byte[6]);
        byte[] encrypted2b = CE.EncryptUpdate(session, new byte[4]);
        byte[] encrypted2c = CE.EncryptFinal(session);
        assertTrue(Arrays.equals(encrypted1, Buf.cat(encrypted2a, encrypted2b, encrypted2c)));

        CE.DecryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] decrypted1 = CE.DecryptPad(session, encrypted1);
        assertTrue(Arrays.equals(plaintext, decrypted1));
        CE.DecryptInit(session, new CKM(CKM.AES_CBC_PAD), aeskey);
        byte[] decrypted2a = CE.DecryptUpdate(session, Buf.substring(encrypted1, 0, 8));
        byte[] decrypted2b = CE.DecryptUpdate(session, Buf.substring(encrypted1, 8, 8));
        byte[] decrypted2c = CE.DecryptFinal(session);
        boolean b = Arrays.equals(plaintext, Buf.cat(decrypted2a, decrypted2b, decrypted2c));
        assertTrue(b);
        log.info(String.format("testEncryptDecrypt: %b", b));
        // System.out.println(
        // "testEncryptDecrypt: " + Arrays.equals(plaintext, Buf.cat(decrypted2a,
        // decrypted2b, decrypted2c)));
    }

    public void testDigest() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.Login(session, CKU.USER, USER_PIN); // Needed depending on HSM policy
        CE.DigestInit(session, new CKM(CKM.SHA256));
        byte[] digested1 = CE.Digest(session, new byte[100]);
        assertEquals(32, digested1.length);
        log.info(String.format("testDigest: digest length (expected 32) = %d", digested1.length));

        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestUpdate(session, new byte[50]);
        CE.DigestUpdate(session, new byte[50]);
        byte[] digested2 = CE.DigestFinal(session);
        boolean b = Arrays.equals(digested1, digested2);
        assertTrue(Arrays.equals(digested1, digested2));
        log.info(String.format("testDigest: Arrays digested1 == digested2: %b", b));

        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "labelaesdigest"),
                new CKA(CKA.ID, "labelaesdigest"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));

        CE.DigestInit(session, new CKM(CKM.SHA256));
        CE.DigestKey(session, aeskey);
        byte[] digestedKey = CE.DigestFinal(session);

        /* TODO: Needs some more tests for the digestedKey */
    }

    public void testSignVerifyRSAPKCS1() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // Different HSMs have a little different requirements on templates, regardless of which are mandatory or not
        // in the P11 spec. To work with as many HSMs as possible, use a good default, as complete as possible, template.
        // On most HSMs you can set CKA_ID after key generations, but some requires adding CKA_ID at generation time
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelrsa-public"),
            new CKA(CKA.ID, "labelrsa"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelrsa-private"),
            new CKA(CKA.ID, "labelrsa"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // Direct sign
        byte[] data = new byte[100];
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);
        log.info(String.format("testSignVerifyRSAPKCS1: signature length (expected 32) = %d", sig1.length));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.Verify(session, data, sig1);
        
        // Using SignUpdate
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        CE.SignUpdate(session, new byte[50]);
        CE.SignUpdate(session, new byte[50]);
        byte[] sig2 = CE.SignFinal(session);
        boolean b = Arrays.equals(sig1, sig2);
        assertTrue(b);
        log.info(String.format("testDitestSignVerifyRSAPKCS1: Signature sig1 == sig2: %b", b));

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig2);

        CE.VerifyInit(session, new CKM(CKM.SHA256_RSA_PKCS), pubKey.value());
        try {
            CE.Verify(session, data, new byte[128]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
            // System.out.println(
            // "testSignVerifyRSAPKCS1: Exception expected " + CKR.SIGNATURE_INVALID + " -
            // Actual exception: "
            // + e.getCKR());
            log.info(String.format(
                    "testSignVerifyRSAPKCS1: Verifying invalid signature. Exception expected %d (%s) - Actual exception %d (%s)",
                    CKR.SIGNATURE_INVALID, CKR.L2S(CKR.SIGNATURE_INVALID), e.getCKR(),
                    CKR.L2S(e.getCKR())));
        }
    }

    public void testSignVerifyRSAPSS() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "label-public"),
            new CKA(CKA.ID, "label"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "label-private"),
            new CKA(CKA.ID, "label"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // RSA-PSS needs parameters, which specifies the padding to be used, matching the hash algorithm 
        byte[] params = ULong.ulong2b(new long[]{CKM.SHA256, CKG.MGF1_SHA256, 32});
        CKM ckm = new CKM(CKM.SHA256_RSA_PKCS_PSS, params);

        // Direct sign
        byte[] data = new byte[100];
        CE.SignInit(session, ckm, privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);

        // System.out.println(
        // "testSignVerifyRSAPSS: " + String.valueOf(128 == sig1.length));
        log.info(String.format("testSignVerifyRSAPSS: signature length (expected 128) = %d", sig1.length));

        CE.VerifyInit(session, ckm, pubKey.value());
        CE.Verify(session, data, sig1);
        
        // Using SignUpdate
        CE.SignInit(session, ckm, privKey.value());
        CE.SignUpdate(session, new byte[50]);
        CE.SignUpdate(session, new byte[50]);
        byte[] sig2 = CE.SignFinal(session);
        // RSA-PSS uses randomness, so two signatures can not be compared as with RSA PKCS#1
        //assertTrue(Arrays.equals(sig1, sig2));

        CE.VerifyInit(session, ckm, pubKey.value());
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyUpdate(session, new byte[50]);
        CE.VerifyFinal(session, sig2);

        CE.VerifyInit(session, ckm, pubKey.value());
        try {
            CE.Verify(session, data, new byte[128]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
            // System.out.println(
            // "testSignVerifyRSAPSS: Exception expected " + CKR.SIGNATURE_INVALID + " -
            // Actual exception: "
            // + e.getCKR());
            log.info(String.format(
                    "testSignVerifyRSAPSS: Verifying invalid signature. Exception expected %d (%s) - Actual exception %d (%s)",
                    CKR.SIGNATURE_INVALID, CKR.L2S(CKR.SIGNATURE_INVALID), e.getCKR(),
                    CKR.L2S(e.getCKR())));
        }
    }

    public void testSignVerifyECDSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms Specification 
        //   Version 2.40 section 2.3.3 - ECDSA public key objects
        // We use a P-256 key (also known as secp256r1 or prime256v1), the oid 1.2.840.10045.3.1.7 
        //   has DER encoding in Hex 06082a8648ce3d030107
        // DER-encoding of an ANSI X9.62 Parameters, also known as "EC domain parameters".
        //   See X9.62-1998 Public Key Cryptography For The Financial Services Industry: 
        //   The Elliptic Curve Digital Signature Algorithm (ECDSA), page 27.
        byte[] ecCurveParams = Hex.s2b("06082a8648ce3d030107");
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.EC_PARAMS, ecCurveParams),
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

        // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
        byte[] data = new byte[32]; // SHA256 hash is 32 bytes
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);
        log.info(String.format("testSignVerifyECDSA: signature length (expected 64) = %d", sig1.length));
        // System.out.println("testSignVerifyECDSA: " + String.valueOf(64 ==
        // sig1.length));

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        CE.Verify(session, data, sig1);

        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        try {
            CE.Verify(session, data, new byte[64]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            // System.out.println(
            // "testSignVerifyECDSA: Exception expected " + CKR.SIGNATURE_INVALID + " : "
            // + CKR.L2S(CKR.SIGNATURE_INVALID) + " - Actual exception: "
            // + e.getCKR() + " : " + CKR.L2S(e.getCKR()));
            // Utimaco Simulator exception: GENERAL_ERROR instead of SIGNATURE_INVALID, when
            // no real signature
            assertEquals("Failure with invalid signature data should be CKR.GENERAL_ERROR", CKR.GENERAL_ERROR,
                    e.getCKR());
            log.info(String.format(
                    "testSignVerifyECDSA: Verifying invalid signature. Exception expected %d (%s) - Actual exception %d (%s)",
                    CKR.GENERAL_ERROR, CKR.L2S(CKR.GENERAL_ERROR), e.getCKR(),
                    CKR.L2S(e.getCKR())));
        }
    }

    /** https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061191
     */
    public void testSignVerifyEdDSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // CKM_EC_EDWARDS_KEY_PAIR_GEN
        /*
            The mechanism can only generate EC public/private key pairs over the curves edwards25519 and edwards448 as defined in RFC 8032 or the curves 
            id-Ed25519 and id-Ed448 as defined in RFC 8410. These curves can only be specified in the CKA_EC_PARAMS attribute of the template for the 
            public key using the curveName or the oID methods 
        */
        // CKM_EDDSA (signature mechanism)
        /*
            CK_EDDSA_PARAMS is a structure that provides the parameters for the CKM_EDDSA signature mechanism.  The structure is defined as follows:
            typedef struct CK_EDDSA_PARAMS {
                CK_BBOOL     phFlag;
                CK_ULONG     ulContextDataLen;
                CK_BYTE_PTR  pContextData;
            }  CK_EDDSA_PARAMS
        */
        // CK_EDDSA_PARAMS (no params means Ed25519 in keygen?)
        // CK_EDDSA_PARAMS_PTR is a pointer to a CK_EDDSA_PARAMS
        // CKK_EC_EDWARDS (private and public key)
        
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms Specification Version 2.40 section 2.3.3 - ECDSA public key objects
        /* DER-encoding of an ANSI X9.62 Parameters, also known as "EC domain parameters". */
        // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570
        // byte[] ecCurveParams = Hex.s2b("06032b6570");
        CKA[] pubTempl = new CKA[] {
                new CKA(CKA.EC_PARAMS, "edwards25519"),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, false),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "label-public"),
            new CKA(CKA.ID, "label"),
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
            new CKA(CKA.LABEL, "label-private"),
            new CKA(CKA.ID, "label"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.EC_EDWARDS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // Direct sign, PKCS#11 "2.3.14 EdDSA"
        byte[] data = new byte[32];
        CE.SignInit(session, new CKM(CKM.EDDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);
        log.info(String.format("testSignVerifyEdDSA: signature length (expected 64) = %d", sig1.length));

        CE.VerifyInit(session, new CKM(CKM.EDDSA), pubKey.value());
        CE.Verify(session, data, sig1);

        CE.VerifyInit(session, new CKM(CKM.EDDSA), pubKey.value());
        try {
            CE.Verify(session, data, new byte[64]);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID, e.getCKR());
            log.info(String.format(
                    "testSignVerifyEdDSA: Verifying invalid signature. Exception expected %d (%s) - Actual exception %d (%s)",
                    CKR.SIGNATURE_INVALID, CKR.L2S(CKR.SIGNATURE_INVALID), e.getCKR(),
                    CKR.L2S(e.getCKR())));
        }
    }

    /** SignRecoverInit and VerifyRecoverInit is not supported on all HSMs, 
     * so it has a separate test that may expect to fail with FUNCTION_NOT_SUPPORTED
     */
    public void testSignVerifyRecoveryRSA() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        CE.LoginUser(session, USER_PIN);
        // See comments on the method testSignVerifyRSA
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelrsa2-public"),
            new CKA(CKA.ID, "labelrsa2"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelrsa2-private"),
            new CKA(CKA.ID, "labelrsa2"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        byte[] data = new byte[100];
        CE.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(128, sig1.length);
        log.info(String.format("testSignVerifyRecoveryRSA: signature length (expected 128) = %d", sig1.length));

        data = new byte[10];
        CE.SignRecoverInit(session, new CKM(CKM.RSA_PKCS), privKey.value());
        byte[] sigrec1 = CE.SignRecover(session, data);

        /*
         * TODO: Antes o expected era 64 bytes para o sig1 e dava erro. Ver se é mesmo
         * 128 bytes
         * para estes dados.
         */
        assertEquals(128, sigrec1.length);
        log.info(String.format("testSignVerifyRecoveryRSA: signature length (expected 128) = %d", sigrec1.length));

        CE.VerifyRecoverInit(session, new CKM(CKM.RSA_PKCS), pubKey.value());
        byte[] recdata = CE.VerifyRecover(session, sigrec1);
        boolean b = Arrays.equals(data, recdata);
        assertTrue(b);
        log.info(String.format("testSignVerifyRecoveryRSA: data correctly recovered = %b", b));
    }

//    public static native long C_DigestEncryptUpdate(long session, byte[] part, long part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native long C_DecryptDigestUpdate(long session, byte[] encrypted_part, long encrypted_part_len, byte[] part, LongRef part_len);
//    public static native long C_SignEncryptUpdate(long session, byte[] part, long part_len, byte[] encrypted_part, LongRef encrypted_part_len);
//    public static native long C_DecryptVerifyUpdate(long session, byte[] encrypted_part, long encrypted_part_len, byte[] part, LongRef part_len);


    public void testGenerateKeyWrapUnwrap() {
        long session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);

//        CKA[] secTempl = new CKA[] {
//                new CKA(CKA.VALUE_LEN, 32),
//                new CKA(CKA.LABEL, "labelwrap"),
//                new CKA(CKA.ID, "labelwrap"),
//                new CKA(CKA.TOKEN, false),
//                new CKA(CKA.SENSITIVE, false),
//                new CKA(CKA.EXTRACTABLE, true),
//                new CKA(CKA.ENCRYPT, true),
//                new CKA(CKA.DECRYPT, true),
//                new CKA(CKA.DERIVE, true),
//        };
//        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN), secTempl);
        long aeskey = CE.GenerateKey(session, new CKM(CKM.AES_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 32),
                new CKA(CKA.LABEL, "labelwrap"),
                new CKA(CKA.ID, "labelwrap"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.EXTRACTABLE, true),
                new CKA(CKA.DERIVE, true));
        byte[] aeskeybuf = CE.GetAttributeValue(session, aeskey, CKA.VALUE).getValue();

        // See comments on the method testSignVerifyRSA
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.MODULUS_BITS, 1024),
            new CKA(CKA.PUBLIC_EXPONENT, Hex.s2b("010001")),
            new CKA(CKA.WRAP, true),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, true),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, "labelrsa3-public"),
            new CKA(CKA.ID, "labelrsa3"),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, true),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, true),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, "labelrsa3-private"),
            new CKA(CKA.ID, "labelrsa3"),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        CE.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);

        // Key wrapping, i.e. exporting a key from the HSM. Wrapping with RSA means you wrap (encrypt) the key 
        // with the RSA public key and you unwrap (decrypt) it with the RSA private key
        // http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/csprd02/pkcs11-curr-v2.40-csprd02.html#_Toc387327730
        byte[] wrapped = CE.WrapKey(session, new CKM(CKM.RSA_PKCS), pubKey.value(), aeskey);

        // We need to provide a full set of attributes for the secret key in order to unwrap it inside the HSM
        // Unwrapping is done with the RSA private key, i.e. the secret key is never exposed unencrypted outside
        // of the HSM (if we had generated the secret key with CKA.EXTRACTABLE=false that is)
        CKA[] secTemplUnwrap = new CKA[] {
                new CKA(CKA.CLASS, CKO.SECRET_KEY),
                new CKA(CKA.KEY_TYPE, CKK.AES),
                new CKA(CKA.LABEL, "labelunwrap"),
                new CKA(CKA.ID, "labelunwrap"),
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.EXTRACTABLE, true),
                new CKA(CKA.ENCRYPT, true),
                new CKA(CKA.DECRYPT, true),
                new CKA(CKA.DERIVE, true),
        };
        long aeskey2 = CE.UnwrapKey(session, new CKM(CKM.RSA_PKCS), privKey.value(), wrapped, secTemplUnwrap);
        byte[] aeskey2buf = CE.GetAttributeValue(session, aeskey2, CKA.VALUE).getValue();
        boolean b = Arrays.equals(aeskey2buf, aeskeybuf);
        assertTrue(b);
        log.info(String.format("testGenerateKeyWrapUnwrap: aekeybuf == aeskeybuf2 : %b", b));
    }

    public void testPTKDES3Derive() {
        long session = CE.OpenSession(TESTSLOT);
        CE.LoginUser(session, USER_PIN);

        long des3key = CE.GenerateKey(session, new CKM(CKM.DES3_KEY_GEN),
                new CKA(CKA.VALUE_LEN, 24),
                new CKA(CKA.LABEL, "label"),
                new CKA(CKA.SENSITIVE, false),
                new CKA(CKA.DERIVE, true));
        byte[] des3keybuf = CE.GetAttributeValue(session, des3key, CKA.VALUE).getValue();
        
      CE.DeriveKey(session, new CKM(CKM.VENDOR_PTK_DES3_DERIVE_CBC, new byte[32]), des3key);
    }
    
    public void testRandom() {
        long session = CE.OpenSession(TESTSLOT, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        /* TODO: Needed to login (in Utimaco) */
        CE.LoginUser(session, USER_PIN);

        byte[] buf = new byte[16];
        CE.SeedRandom(session, buf);
        CE.GenerateRandom(session, buf);
        byte[] buf2 = CE.GenerateRandom(session, 16);

        // System.out.println("testRandom: " + buf2);
        log.info(String.format("testRandom: random value : %s", Hex.b2s(buf2)));
    }

//    public static native long C_GetFunctionStatus(long session);
//    public static native long C_CancelFunction(long session);


//    public static native long C_WaitForSlotEvent(long flags, LongRef slot, Pointer pReserved);
//    public static native long C_SetOperationState(long session, byte[] operation_state, long operation_state_len, long encryption_key, long authentication_key);
}
