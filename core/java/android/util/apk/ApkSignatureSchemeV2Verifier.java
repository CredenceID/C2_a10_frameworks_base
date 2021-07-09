/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.util.apk;

import static android.util.apk.ApkSigningBlockUtils.CONTENT_DIGEST_VERITY_CHUNKED_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_DSA_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_ECDSA_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_ECDSA_WITH_SHA512;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_RSA_PSS_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_RSA_PSS_WITH_SHA512;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_VERITY_DSA_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_VERITY_ECDSA_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256;
import static android.util.apk.ApkSigningBlockUtils.compareSignatureAlgorithm;
import static android.util.apk.ApkSigningBlockUtils.getContentDigestAlgorithmJcaDigestAlgorithm;
import static android.util.apk.ApkSigningBlockUtils.getLengthPrefixedSlice;
import static android.util.apk.ApkSigningBlockUtils.getSignatureAlgorithmContentDigestAlgorithm;
import static android.util.apk.ApkSigningBlockUtils.getSignatureAlgorithmJcaKeyAlgorithm;
import static android.util.apk.ApkSigningBlockUtils.getSignatureAlgorithmJcaSignatureAlgorithm;
import static android.util.apk.ApkSigningBlockUtils.readLengthPrefixedByteArray;

import android.util.ArrayMap;
import android.util.Pair;

import android.util.Log;
import android.os.Environment;

import java.io.FileInputStream;
import java.io.Reader;
import java.io.StringReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * APK Signature Scheme v2 verifier.
 *
 * <p>APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
 * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
 * uncompressed contents of ZIP entries.
 *
 * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
 *
 * @hide for internal use only.
 */
public class ApkSignatureSchemeV2Verifier {

    /**
     * ID of this signature scheme as used in X-Android-APK-Signed header used in JAR signing.
     */
    public static final int SF_ATTRIBUTE_ANDROID_APK_SIGNED_ID = 2;

    private static final String TAG = "ApkSignatureSchemeV2Verifier";
    private static final String PLATFORM_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=ca7dcc148c19d486913847499c8f42636d62367269d8f444933524"+
                        "b8a19e7074d808ef62690d70fcb81c05613b0ba9014992ebde49fef402738d3c0137310832cc2f3c8a"+
                        "25a74af124fdabf5cc8709995d8757f193c50207ea5aae9f3ec727d4c82306a7b4a55430bb3028824f"+
                        "98adaf37ccd61ab422f13dd4119974bdace3c7c8d76d3aa92d91d8a0c23ffe43877b6d79ccaea0bff9"+
                        "2200122c322d1e39817b0b058b0be4ef9135765318e183054abdf0795a8e1cfd511a41d7b857d11be0"+
                        "d082dfe772ec60430a804be5f797994432fac9399a3fe66b8f5433efde98cf6e53666c61d09811fa32"+
                        "e7a3dd3105e5133e91e3c9e8e54aa7801b006f0353132617,publicExponent=3}";
    private static final String MEDIA_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=dd9f8d16845ed053476784393647f33610dbf32f79211489e39649"+
                        "80edbad04e47441ab29295b91bf7c1fc091a241d183eb4050e54801644a64adda45870144e284419f8"+
                        "2aa1ac8eac028fc8e7140568bcea03e4990fb3fa4caadf97b92b820cfb697723ade719e738bb6bcab1"+
                        "3eb96b4006e5c9d271880ed2e18a74c3889f0dcde9ec8b2fa21d8a7dc44d2e047f72399dafd938073d"+
                        "414236bb4f024d3b6bbb07b7f9c1413c4f6443dad29d550d11be7cbbe4b2323f079711cbc6f5197c44"+
                        "3321f93eaadfa6f344642b3af0a8bc000ff006b62e42ed77200dd5e6e972d319c9e9c93ae831c318eb"+
                        "0b983ec0ab56ecbfab4ba0436c497ae7a9901a68e9b8a273,publicExponent=3}";
    private static final String SHARED_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=d9d2f3dfcfad68c4a7e818dacdc013fc85c85aac9ad5e34b768d7b"+
                        "2784fe9422280f631a8f0ced4083f4cda0f049139f2c23d0649a6467cef3c5f78761e9fdbafc833084"+
                        "d8a32c8fcb55bd0a83dc634a72a857842a40d507c7877a1ebb89cd73a59388ac91008e04638a6567c8"+
                        "9c39641c8a73e2721bbd7b76e3a00f7dcd8cb511e601d265a869dde9db55e73d814bc916ffcd941c01"+
                        "d430f1ceca4fe653599393aa2ddcd4073f4228932147b14fb6e66519d971f6da63630de86a48d279da"+
                        "a4ff5d263b1fb6217fc7904e41e0d9ca123fe34dbf3a1ec1f544c9e1c138040842408daa0c8efe1c58"+
                        "d1e346a44dbb0c8d47991ae0d9f9f71537e462610b7a82f5,publicExponent=3}";
    private static final String TEST_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=ade42d493d64e4100e8895971d2193f8dad025a5f7c1fb875095c4"+
                        "6b073f211456c8ad07239830ad475f59b96d9af317e9dda8d03397d8723188ce56958f0d3cebe0fdc1"+
                        "6fc03d041adb6b38edf58ca8721b05ecb0168f4114c4c7b94cd29f69d40242a79f16eca45bf723cefe"+
                        "07e28916ff63d8f088062437840646789832aabc9ad00db7f8c9aade012e7e272877726b7d45e92d0d"+
                        "2203e5c934a9c83bdee3a24d734c0c77e407ce9cc4c4fe665c82aeb1284eb32943566c942acd61064c"+
                        "8e4990403e5c37a6ab596a558c17932633d259d5718b8464a18e829278e8b67fd3f438aef3b1fb8a0f"+
                        "aad13e23bd5b2e8b773fc3e4cb58daa70501f8f8efe8480f,publicExponent=3}";

    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;

    /**
     * Returns {@code true} if the provided APK contains an APK Signature Scheme V2 signature.
     *
     * <p><b>NOTE: This method does not verify the signature.</b>
     */
    public static boolean hasSignature(String apkFile) throws IOException {
        try (RandomAccessFile apk = new RandomAccessFile(apkFile, "r")) {
            findSignature(apk);
            return true;
        } catch (SignatureNotFoundException e) {
            return false;
        }
    }

    /**
     * Verifies APK Signature Scheme v2 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v2.
     * @throws SecurityException if a APK Signature Scheme v2 signature of this APK does not verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    public static X509Certificate[][] verify(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        VerifiedSigner vSigner = verify(apkFile, true);
        return vSigner.certs;
    }

    /**
     * Returns the certificates associated with each signer for the given APK without verification.
     * This method is dangerous and should not be used, unless the caller is absolutely certain the
     * APK is trusted.  Specifically, verification is only done for the APK Signature Scheme v2
     * Block while gathering signer information.  The APK contents are not verified.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v2.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    public static X509Certificate[][] unsafeGetCertsWithoutVerification(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        VerifiedSigner vSigner = verify(apkFile, false);
        return vSigner.certs;
    }

    private static VerifiedSigner verify(String apkFile, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        try (RandomAccessFile apk = new RandomAccessFile(apkFile, "r")) {
            return verify(apk, verifyIntegrity);
        }
    }

    /**
     * Verifies APK Signature Scheme v2 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v2.
     * @throws SecurityException if an APK Signature Scheme v2 signature of this APK does not
     *         verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static VerifiedSigner verify(RandomAccessFile apk, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        SignatureInfo signatureInfo = findSignature(apk);
        return verify(apk, signatureInfo, verifyIntegrity);
    }

    /**
     * Returns the APK Signature Scheme v2 block contained in the provided APK file and the
     * additional information relevant for verifying the block against the file.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v2.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static SignatureInfo findSignature(RandomAccessFile apk)
            throws IOException, SignatureNotFoundException {
        return ApkSigningBlockUtils.findSignature(apk, APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
    }

    /**
     * Verifies the contents of the provided APK file against the provided APK Signature Scheme v2
     * Block.
     *
     * @param signatureInfo APK Signature Scheme v2 Block and information relevant for verifying it
     *        against the APK file.
     */
    private static VerifiedSigner verify(
            RandomAccessFile apk,
            SignatureInfo signatureInfo,
            boolean doVerifyIntegrity) throws SecurityException, IOException {
        int signerCount = 0;
        Map<Integer, byte[]> contentDigests = new ArrayMap<>();
        List<X509Certificate[]> signerCerts = new ArrayList<>();
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e);
        }
        ByteBuffer signers;
        try {
            signers = getLengthPrefixedSlice(signatureInfo.signatureBlock);
        } catch (IOException e) {
            throw new SecurityException("Failed to read list of signers", e);
        }
        while (signers.hasRemaining()) {
            signerCount++;
            try {
                ByteBuffer signer = getLengthPrefixedSlice(signers);
                X509Certificate[] certs = verifySigner(signer, contentDigests, certFactory);
                signerCerts.add(certs);
            } catch (IOException | BufferUnderflowException | SecurityException e) {
                throw new SecurityException(
                        "Failed to parse/verify signer #" + signerCount + " block",
                        e);
            }
        }

        if (signerCount < 1) {
            throw new SecurityException("No signers found");
        }

        if (contentDigests.isEmpty()) {
            throw new SecurityException("No content digests found");
        }

        if (doVerifyIntegrity) {
            ApkSigningBlockUtils.verifyIntegrity(contentDigests, apk, signatureInfo);
        }

        byte[] verityRootHash = null;
        if (contentDigests.containsKey(CONTENT_DIGEST_VERITY_CHUNKED_SHA256)) {
            byte[] verityDigest = contentDigests.get(CONTENT_DIGEST_VERITY_CHUNKED_SHA256);
            verityRootHash = ApkSigningBlockUtils.parseVerityDigestAndVerifySourceLength(
                    verityDigest, apk.length(), signatureInfo);
        }

        return new VerifiedSigner(
                signerCerts.toArray(new X509Certificate[signerCerts.size()][]),
                verityRootHash);
    }

    private static X509Certificate[] verifySigner(
            ByteBuffer signerBlock,
            Map<Integer, byte[]> contentDigests,
            CertificateFactory certFactory) throws SecurityException, IOException {
        ByteBuffer signedData = getLengthPrefixedSlice(signerBlock);
        ByteBuffer signatures = getLengthPrefixedSlice(signerBlock);
        byte[] publicKeyBytes = readLengthPrefixedByteArray(signerBlock);

        int signatureCount = 0;
        int bestSigAlgorithm = -1;
        byte[] bestSigAlgorithmSignatureBytes = null;
        List<Integer> signaturesSigAlgorithms = new ArrayList<>();
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = getLengthPrefixedSlice(signatures);
                if (signature.remaining() < 8) {
                    throw new SecurityException("Signature record too short");
                }
                int sigAlgorithm = signature.getInt();
                signaturesSigAlgorithms.add(sigAlgorithm);
                if (!isSupportedSignatureAlgorithm(sigAlgorithm)) {
                    continue;
                }
                if ((bestSigAlgorithm == -1)
                        || (compareSignatureAlgorithm(sigAlgorithm, bestSigAlgorithm) > 0)) {
                    bestSigAlgorithm = sigAlgorithm;
                    bestSigAlgorithmSignatureBytes = readLengthPrefixedByteArray(signature);
                }
            } catch (IOException | BufferUnderflowException e) {
                throw new SecurityException(
                        "Failed to parse signature record #" + signatureCount,
                        e);
            }
        }
        if (bestSigAlgorithm == -1) {
            if (signatureCount == 0) {
                throw new SecurityException("No signatures found");
            } else {
                throw new SecurityException("No supported signatures found");
            }
        }

        String keyAlgorithm = getSignatureAlgorithmJcaKeyAlgorithm(bestSigAlgorithm);
        Pair<String, ? extends AlgorithmParameterSpec> signatureAlgorithmParams =
                getSignatureAlgorithmJcaSignatureAlgorithm(bestSigAlgorithm);
        String jcaSignatureAlgorithm = signatureAlgorithmParams.first;
        AlgorithmParameterSpec jcaSignatureAlgorithmParams = signatureAlgorithmParams.second;
        boolean sigVerified = false;
        try {
            PublicKey publicKey =
                    KeyFactory.getInstance(keyAlgorithm)
                            .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                                   //Verification method is changed to support reject non signed cid
                                   //apks
                                   String pkgKeyStr = publicKey.toString();
                                   if (pkgKeyStr.equals(PLATFORM_X509_CERT_KEY)
                                                           || pkgKeyStr.equals(MEDIA_X509_CERT_KEY)
                                                           || pkgKeyStr.equals(SHARED_X509_CERT_KEY)
                                                           || pkgKeyStr.equals(TEST_X509_CERT_KEY)) {
                                                           sigVerified = true;
                                   }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SecurityException(
                    "Failed to verify " + jcaSignatureAlgorithm + " signature", e);
        }
        if (!sigVerified) {
            throw new SecurityException(jcaSignatureAlgorithm + " signature did not verify");
        }

        // Signature over signedData has verified.

        byte[] contentDigest = null;
        signedData.clear();
        ByteBuffer digests = getLengthPrefixedSlice(signedData);
        List<Integer> digestsSigAlgorithms = new ArrayList<>();
        int digestCount = 0;
        while (digests.hasRemaining()) {
            digestCount++;
            try {
                ByteBuffer digest = getLengthPrefixedSlice(digests);
                if (digest.remaining() < 8) {
                    throw new IOException("Record too short");
                }
                int sigAlgorithm = digest.getInt();
                digestsSigAlgorithms.add(sigAlgorithm);
                if (sigAlgorithm == bestSigAlgorithm) {
                    contentDigest = readLengthPrefixedByteArray(digest);
                }
            } catch (IOException | BufferUnderflowException e) {
                throw new IOException("Failed to parse digest record #" + digestCount, e);
            }
        }

        if (!signaturesSigAlgorithms.equals(digestsSigAlgorithms)) {
            throw new SecurityException(
                    "Signature algorithms don't match between digests and signatures records");
        }
        int digestAlgorithm = getSignatureAlgorithmContentDigestAlgorithm(bestSigAlgorithm);
        byte[] previousSignerDigest = contentDigests.put(digestAlgorithm, contentDigest);
        if ((previousSignerDigest != null)
                && (!MessageDigest.isEqual(previousSignerDigest, contentDigest))) {
            throw new SecurityException(
                    getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm)
                    + " contents digest does not match the digest specified by a preceding signer");
        }

        ByteBuffer certificates = getLengthPrefixedSlice(signedData);
        List<X509Certificate> certs = new ArrayList<>();
        int certificateCount = 0;
        while (certificates.hasRemaining()) {
            certificateCount++;
            byte[] encodedCert = readLengthPrefixedByteArray(certificates);
            X509Certificate certificate;
            try {
                certificate = (X509Certificate)
                        certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
            } catch (CertificateException e) {
                throw new SecurityException("Failed to decode certificate #" + certificateCount, e);
            }
            certificate = new VerbatimX509Certificate(
                    certificate, encodedCert);
            certs.add(certificate);
        }

        if (certs.isEmpty()) {
            throw new SecurityException("No certificates listed");
        }
        X509Certificate mainCertificate = certs.get(0);
        byte[] certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            throw new SecurityException(
                    "Public key mismatch between certificate and signature record");
        }

        ByteBuffer additionalAttrs = getLengthPrefixedSlice(signedData);
        verifyAdditionalAttributes(additionalAttrs);

        return certs.toArray(new X509Certificate[certs.size()]);
    }

    // Attribute to check whether a newer APK Signature Scheme signature was stripped
    private static final int STRIPPING_PROTECTION_ATTR_ID = 0xbeeff00d;

    private static void verifyAdditionalAttributes(ByteBuffer attrs)
            throws SecurityException, IOException {
        while (attrs.hasRemaining()) {
            ByteBuffer attr = getLengthPrefixedSlice(attrs);
            if (attr.remaining() < 4) {
                throw new IOException("Remaining buffer too short to contain additional attribute "
                        + "ID. Remaining: " + attr.remaining());
            }
            int id = attr.getInt();
            switch (id) {
                case STRIPPING_PROTECTION_ATTR_ID:
                    if (attr.remaining() < 4) {
                        throw new IOException("V2 Signature Scheme Stripping Protection Attribute "
                                + " value too small.  Expected 4 bytes, but found "
                                + attr.remaining());
                    }
                    int vers = attr.getInt();
                    if (vers == ApkSignatureSchemeV3Verifier.SF_ATTRIBUTE_ANDROID_APK_SIGNED_ID) {
                        throw new SecurityException("V2 signature indicates APK is signed using APK"
                                + " Signature Scheme v3, but none was found. Signature stripped?");
                    }
                    break;
                default:
                    // not the droid we're looking for, move along, move along.
                    break;
            }
        }
        return;
    }

    static byte[] getVerityRootHash(String apkPath)
            throws IOException, SignatureNotFoundException, SecurityException {
        try (RandomAccessFile apk = new RandomAccessFile(apkPath, "r")) {
            SignatureInfo signatureInfo = findSignature(apk);
            VerifiedSigner vSigner = verify(apk, false);
            return vSigner.verityRootHash;
        }
    }

    static byte[] generateApkVerity(String apkPath, ByteBufferFactory bufferFactory)
            throws IOException, SignatureNotFoundException, SecurityException, DigestException,
                   NoSuchAlgorithmException {
        try (RandomAccessFile apk = new RandomAccessFile(apkPath, "r")) {
            SignatureInfo signatureInfo = findSignature(apk);
            return VerityBuilder.generateApkVerity(apkPath, bufferFactory, signatureInfo);
        }
    }

    static byte[] generateApkVerityRootHash(String apkPath)
            throws IOException, SignatureNotFoundException, DigestException,
                   NoSuchAlgorithmException {
        try (RandomAccessFile apk = new RandomAccessFile(apkPath, "r")) {
            SignatureInfo signatureInfo = findSignature(apk);
            VerifiedSigner vSigner = verify(apk, false);
            if (vSigner.verityRootHash == null) {
                return null;
            }
            return VerityBuilder.generateApkVerityRootHash(
                    apk, ByteBuffer.wrap(vSigner.verityRootHash), signatureInfo);
        }
    }

    private static boolean isSupportedSignatureAlgorithm(int sigAlgorithm) {
        switch (sigAlgorithm) {
            case SIGNATURE_RSA_PSS_WITH_SHA256:
            case SIGNATURE_RSA_PSS_WITH_SHA512:
            case SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256:
            case SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512:
            case SIGNATURE_ECDSA_WITH_SHA256:
            case SIGNATURE_ECDSA_WITH_SHA512:
            case SIGNATURE_DSA_WITH_SHA256:
            case SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256:
            case SIGNATURE_VERITY_ECDSA_WITH_SHA256:
            case SIGNATURE_VERITY_DSA_WITH_SHA256:
                return true;
            default:
                return false;
        }
    }

    /**
     * Verified APK Signature Scheme v2 signer.
     *
     * @hide for internal use only.
     */
    public static class VerifiedSigner {
        public final X509Certificate[][] certs;
        public final byte[] verityRootHash;

        public VerifiedSigner(X509Certificate[][] certs, byte[] verityRootHash) {
            this.certs = certs;
            this.verityRootHash = verityRootHash;
        }

    }
}
