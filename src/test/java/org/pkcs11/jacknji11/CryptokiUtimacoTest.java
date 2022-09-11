/*
 * Copyright 2022 - Devise Futures, Lda. All rights reserved.
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

import junit.framework.TestCase;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * JUnit tests for jacknji11.
 * Test Edward curves (Ed25519) in Utimaco HSM (Cryptoserver v. 4.31)
 * 
 * Based on existing tests in CriptokiTest.java
 * 
 * @author José Miranda (jose.miranda@devisefutures.com)
 * @author Luís Pereira (luis.pereira@devisefutures.com)
 */
public class CryptokiUtimacoTest extends TestCase {
        private static final Log log = LogFactory.getLog(CryptokiUtimacoTest.class);

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

        /**
         * Test Ed25519 signature and verification using the HSM
         */
        public void testSignVerifyEd25519() {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
                byte[] data = "Message to be signed!!".getBytes();
                CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
                byte[] sig1 = CE.Sign(session, data);

                assertEquals(64, sig1.length);
                log.info(String.format("testSignVerifyEd25519: Signature generated with length (should be 64) ==  %d",
                                sig1.length));

                // Verify valid signature
                CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
                try {
                        CE.Verify(session, data, sig1);
                        log.info("testSignVerifyEd25519: Valid Signature verified");
                } catch (CKRException e) {
                        assertNull("Valid signature verification failed", e.getCKR());
                }

                // Verify if two signatures of the same data are the same signature
                CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
                byte[] sig3 = CE.Sign(session, data);

                assertEquals("Signatures are not the same.", true, Hex.b2s(sig1).equals(Hex.b2s(sig3)));
                log.info(String.format("testSignVerifyEd25519: Signatures are the same: \n\t sig1 = %s \n\t sig3 = %s",
                                Hex.b2s(sig1), Hex.b2s(sig3)));

                byte[] data1 = new byte[256];
                CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
                byte[] sig2 = CE.Sign(session, data1);

                // Verify invalid signature
                CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
                try {
                        CE.Verify(session, data, sig2);
                        fail("CE Verify with no real signature should throw exception");
                } catch (CKRException e) {
                        assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID",
                                        CKR.SIGNATURE_INVALID,
                                        e.getCKR());
                        log.info(String.format(
                                        "testSignVerifyEd25519: Verifying invalid signature. Exception expected %d (%s) - Actual exception %d (%s)",
                                        CKR.SIGNATURE_INVALID, CKR.L2S(CKR.SIGNATURE_INVALID), e.getCKR(),
                                        CKR.L2S(e.getCKR())));
                }
        }

        /**
         * Test Slot access and info obtained
         */
        public void testGetSlotInfo() {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                // Get slot info
                CK_SLOT_INFO info = new CK_SLOT_INFO();
                CE.GetSlotInfo(TESTSLOT, info);
                log.info(String.format("testGetSlotInfo - Testslot info: %d\n%s", TESTSLOT, info));

                // Get token info
                CK_TOKEN_INFO tinfo = new CK_TOKEN_INFO();
                CE.GetTokenInfo(TESTSLOT, tinfo);
                log.info(String.format("testGetSlotInfo - Token info:\n%s", tinfo));
        }

        /**
         * Test Ed25519 key pair genertion
         */
        public void testKeyPairEd25519() {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                log.info(String.format(
                                "testKeyPairEd25519: edwards25519 keypair generated. PublicKey handle: %d, PrivKey handle: %d",
                                pubKey.value(), privKey.value()));

                // GET public key value (CKA.VALUE)
                byte[] publicKey = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE).getValue();
                assertEquals(32, publicKey.length);
                log.info(String.format(
                                "testKeyPairEd25519: public key size (should be 32 bytes) = %d - value = %s",
                                publicKey.length, Hex.b2s(publicKey)));

                // Get public key EC point (CKA.EC_POINT)
                byte[] ecPoint = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_POINT).getValue();
                log.info(String.format("testKeyPairEd25519: EC_POINT length = %d - value = %s",
                                ecPoint.length, Hex.b2s(ecPoint)));

                // Get public key EC params (CKA.EC_PARAMS)
                byte[] ecParams = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_PARAMS).getValue();
                log.info(String.format("testKeyPairEd25519: EC_PARAMS length = %d - value = %s",
                                ecParams.length, Hex.b2s(ecParams)));

                // CKA.EC_POINT is the public key - EC points - (CKA.VALUE) in an OCTET string.
                // The ASN.1 tag for OCTET STRING is 0x04, and the length of that string is 32
                // bytes (0x20 in hex). So, CKA.EC_POINT == 0420 + CKA.VALUE.
                // EC points - pairs of integer coordinates {x, y}, laying on the curve.
                assertEquals(Hex.b2s(publicKey), Hex.b2s(ecPoint).substring(4));

                // Get private key
                try {
                        final byte[] privateKey = CE.GetAttributeValue(session, privKey.value(), CKA.VALUE).getValue();
                        fail("testKeyPairEd25519: Obtaining private key value should throw exception");
                } catch (CKRException e) {
                        assertEquals("testKeyPairEd25519: Failure obtaining private key, should be CKR.ATTRIBUTE_SENSITIVE.",
                                        CKR.ATTRIBUTE_SENSITIVE,
                                        e.getCKR());
                        log.info(String.format("testKeyPairEd25519: Failure obtaining private key, as expected: %s",
                                        CKR.L2S(e.getCKR())));
                }
        }

        /**
         * Test Ed25519 public key export
         */
        public void testExportPublicKey() {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                // Public key information for ed255619 is stored in CKA.VALUE
                CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

                // Create EdDSA spec and PublicKey using net.i2p.crypto library
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
                EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
                PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);
                log.info(String.format("testExportPublicKey: PublicKey: %s", Hex.b2s(pubKey2.getEncoded())));
                log.info(String.format("testExportPublicKey: PublicKey Format: %s", pubKey2.getFormat()));

                // Encode as PEM for export
                byte[] data = pubKey2.getEncoded();
                String base64encoded = new String(Base64.encode(data));
                String pemFormat = "-----BEGIN PUBLIC KEY-----\n" + base64encoded + "\n-----END PUBLIC KEY-----";
                log.info(String.format("testExportPublicKey: PEM PublicKey: \n%s", pemFormat));

                try {
                        FileWriter myWriter = new FileWriter("pubkey.pem");
                        myWriter.write(pemFormat);
                        myWriter.close();
                        log.info("testExportPublicKey: PEM PublicKey successfully exported to file pubkey.pem");
                } catch (IOException e) {
                        System.out.println("testExportPublicKey: An error occurred.");
                        e.printStackTrace();
                }
        }

        /**
         * Test Ed25519 signature verification using java (external to the HSM)
         * 
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeySpecException
         * @throws InvalidParameterSpecException
         * @throws InvalidKeyException
         * @throws SignatureException
         * @throws NoSuchProviderException
         * @throws IOException
         */
        public void testSoftVerifyEd25519()
                        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException,
                        InvalidKeyException, SignatureException, NoSuchProviderException, IOException {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
                byte[] msg = "Message to be signed!!".getBytes("UTF-8");
                CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
                byte[] sig1 = CE.Sign(session, msg);

                // Public key information for ed255619 is stored in CKA.VALUE
                CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

                // Create EdDSA spec and PublicKey using net.i2p.crypto library
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
                EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
                PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);

                log.info(String.format("testSoftVerifyEd25519: message: %s", Hex.b2s(msg)));
                log.info(String.format("testSoftVerifyEd25519: sigString: %s", Hex.b2s(sig1)));
                log.info(String.format("testSoftVerifyEd25519: pubkey: %s", Hex.b2s(pubKey2.getEncoded())));

                // Verify HSM signature, using extracted public key
                EdDSAEngine mEdDSAEngine = new EdDSAEngine();
                mEdDSAEngine.initVerify(pubKey2);
                mEdDSAEngine.update(msg);
                boolean validSig = mEdDSAEngine.verify(sig1);

                assertEquals(true, validSig);
                log.info(String.format("testSoftVerifyEd25519: Signature software verification : %b", validSig));
        }

        /**
         * Test issuance and export Ed25519 certificate (self-signed certificate)
         */
        public void testCertificateEd25519() throws IOException, CertificateException, NoSuchAlgorithmException,
                        SignatureException, InvalidKeyException, NoSuchProviderException, OperatorCreationException,
                        CertException {
                long session = loginSession(TESTSLOT, USER_PIN,
                                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

                // Generate Ed25519 key pair
                LongRef pubKey = new LongRef();
                LongRef privKey = new LongRef();
                generateKeyPairEd25519(session, pubKey, privKey);

                // Public key information for ed255619 is stored in CKA.VALUE
                CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

                // Create EdDSA spec and PublicKey using net.i2p.crypto library
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
                EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
                PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);

                //
                // Create certificate
                // see https://www.mayrhofer.eu.org/post/create-x509-certs-in-java/ e
                // https://stackoverflow.com/questions/39731781/adding-a-signature-to-a-certificate
                //
                Calendar expiry = Calendar.getInstance();
                int validity = 4 * 365;
                expiry.add(Calendar.DAY_OF_YEAR, validity);

                // Certificate structure
                V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
                certGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(System.currentTimeMillis())));

                // DN
                X500NameBuilder dnBuilder = new X500NameBuilder(BCStyle.INSTANCE);
                dnBuilder.addRDN(BCStyle.O, "Test Organization");
                dnBuilder.addRDN(BCStyle.OU, "Test Organization Unit");
                dnBuilder.addRDN(BCStyle.C, "PT");
                dnBuilder.addRDN(BCStyle.CN, "Test Organization Root Certification Authority");
                X500Name subject = dnBuilder.build();
                ASN1Primitive derObject = subject.toASN1Primitive();
                X500Name dnInstance = X500Name.getInstance(derObject);

                certGen.setIssuer(dnInstance);
                certGen.setSubject(dnInstance);
                certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
                certGen.setEndDate(new Time(expiry.getTime()));
                certGen.setSubjectPublicKeyInfo(
                                new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                                ec_point.getValue()));
                // certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey2.getEncoded()));
                certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));

                // Extensions
                ExtensionsGenerator extGen = new ExtensionsGenerator();
                // more info at
                // http://www.java2s.com/example/java-src/pkg/org/metaeffekt/dcc/commons/pki/certificatemanager-98d76.html
                // AIA extension
                List<AccessDescription> list = new ArrayList<>();
                AccessDescription accessDescription = new AccessDescription(AccessDescription.id_ad_ocsp,
                                new GeneralName(GeneralName.uniformResourceIdentifier,
                                                "http://ocsp.root.ca.pt/public/ocsp"));
                list.add(accessDescription);
                AccessDescription[] accessDescriptions = list.toArray(new AccessDescription[list.size()]);
                extGen.addExtension(Extension.authorityInfoAccess, false,
                                new AuthorityInformationAccess(accessDescriptions));
                // Subject key identifier extension
                extGen.addExtension(Extension.subjectKeyIdentifier, false,
                                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(pubKey2));
                // Basic constraints (critical) extension
                extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                // Authority Key Identifier extension (for self-signed certificates
                // subjectKeyIdentifier == authorityKeyIdentifier)
                extGen.addExtension(Extension.authorityKeyIdentifier, false,
                                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(pubKey2));
                // Certificate Policies extension
                List<PolicyInformation> plist = new ArrayList<>();
                plist.add(new PolicyInformation(PolicyQualifierId.id_qt_cps,
                                new DERSequence(new PolicyQualifierInfo(
                                                "https://pki.root.ca.pt/public/politics/cps.html"))));
                PolicyInformation[] plists = plist.toArray(new PolicyInformation[plist.size()]);
                extGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(plists));
                // CRL Distribution points extension
                List<DistributionPoint> crlList = new ArrayList<>();
                DistributionPointName dpName = new DistributionPointName(
                                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                                                "http://pki.root.ca.pt/public/crl/caroot.crl")));
                crlList.add(new DistributionPoint(dpName, null, null));
                DistributionPoint[] crlDistributionPoints = crlList.toArray(new DistributionPoint[crlList.size()]);
                extGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(crlDistributionPoints));
                // keyUsage critical extension
                extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                // add extensions to certifcate structure
                certGen.setExtensions(extGen.generate());

                // generate certificate
                TBSCertificate tbsCert = certGen.generateTBSCertificate();

                log.info(String.format("testCertificateEd25519: Certificate:\n%s", Hex.b2s(tbsCert.getEncoded())));

                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
                dOut.writeObject(tbsCert);

                byte[] certBlock = bOut.toByteArray();

                // since the algorythm is Ed25519 there's no need to create a digest.
                CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
                byte[] signature = CE.Sign(session, certBlock);

                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(tbsCert);
                v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
                v.add(new DERBitString(signature));

                DERSequence der = new DERSequence(v);
                ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                                .generateCertificate(baos);

                // Verify certificate signature
                X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
                boolean r = certHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().build(cert));

                assertEquals(true, r);
                log.info(String.format("testCertificateEd25519: Certificate valid: %b", r));

                // Write certificate to file in PEM format
                StringWriter sw = new StringWriter();
                try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                        pw.writeObject(cert);
                }

                try {
                        FileWriter myWriter = new FileWriter("cert.pem");
                        myWriter.write(sw.toString());
                        myWriter.close();
                        log.info("testCertificateEd25519: PEM certificate successfully exported to file cert.pem");
                } catch (IOException e) {
                        System.out.println("testCertificateEd25519:An error occurred.");
                        e.printStackTrace();
                }
        }

        /**
         * Login to slotID and returns the session handle.
         * 
         * @param slotID      the slot's ID
         * @param userPIN     the normal user's PIN
         * @param flags       from CK_SESSION_INFO
         * @param application passed to callback (ok to leave it null)
         * @param notify      callback function (ok to leave it null)
         * @return session handle
         */
        public long loginSession(long slotID, byte[] userPIN, long flags, NativePointer application,
                        CK_NOTIFY notify) {
                long session = CE.OpenSession(slotID, flags, application, notify);
                CE.LoginUser(session, userPIN);
                return session;
        }

        /**
         * Generates a public-key / private-key Ed25519 pair, create new key objects.
         * 
         * @param session    the session's handle
         * @param publicKey  gets handle of new public key
         * @param privateKey gets handle of new private key
         */
        public void generateKeyPairEd25519(long session, LongRef publicKey, LongRef privateKey) {
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
                                new CKA(CKA.LABEL, "edwards-public"),
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
                                new CKA(CKA.LABEL, "edwards-private"),
                                new CKA(CKA.ID, "labelec"),
                };
                CE.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey,
                                privateKey);
        }

}
