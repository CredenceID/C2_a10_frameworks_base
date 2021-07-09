/*
 * Copyright (C) 2017 The Android Open Source Project
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

import static android.content.pm.PackageManager.INSTALL_PARSE_FAILED_BAD_MANIFEST;
import static android.content.pm.PackageManager.INSTALL_PARSE_FAILED_CERTIFICATE_ENCODING;
import static android.content.pm.PackageManager.INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES;
import static android.content.pm.PackageManager.INSTALL_PARSE_FAILED_NO_CERTIFICATES;
import static android.content.pm.PackageManager.INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION;
import static android.os.Trace.TRACE_TAG_PACKAGE_MANAGER;

import android.content.pm.PackageParser;
import android.content.pm.PackageParser.PackageParserException;
import android.content.pm.PackageParser.SigningDetails.SignatureSchemeVersion;
import android.content.pm.Signature;
import android.os.Trace;
import android.util.jar.StrictJarFile;
import java.security.GeneralSecurityException;

import com.android.internal.util.ArrayUtils;

import libcore.io.IoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;

/**
 * Facade class that takes care of the details of APK verification on
 * behalf of PackageParser.
 *
 * @hide for internal use only.
 */
public class ApkSignatureVerifier {

    private static final AtomicReference<byte[]> sBuffer = new AtomicReference<>();

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

    /**
     * Verifies the provided APK and returns the certificates associated with each signer.
     *
     * @throws PackageParserException if the APK's signature failed to verify.
     */
    public static PackageParser.SigningDetails verify(String apkPath,
            @SignatureSchemeVersion int minSignatureSchemeVersion)
            throws PackageParserException {

        if (minSignatureSchemeVersion > SignatureSchemeVersion.SIGNING_BLOCK_V3) {
            // V3 and before are older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
            + " or newer for package " + apkPath);
        }

        // first try v3
        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "verifyV3");
        try {
            ApkSignatureSchemeV3Verifier.VerifiedSigner vSigner =
                    ApkSignatureSchemeV3Verifier.verify(apkPath);
            Certificate[][] signerCerts = new Certificate[][] { vSigner.certs };
            Signature[] signerSigs = convertToSignatures(signerCerts);
            Signature[] pastSignerSigs = null;
            if (vSigner.por != null) {
                // populate proof-of-rotation information
                pastSignerSigs = new Signature[vSigner.por.certs.size()];
                for (int i = 0; i < pastSignerSigs.length; i++) {
                    pastSignerSigs[i] = new Signature(vSigner.por.certs.get(i).getEncoded());
                    pastSignerSigs[i].setFlags(vSigner.por.flagsList.get(i));
                }
            }
            return new PackageParser.SigningDetails(
                    signerSigs, SignatureSchemeVersion.SIGNING_BLOCK_V3,
                    pastSignerSigs);
        } catch (SignatureNotFoundException e) {
            // not signed with v3, try older if allowed
            if (minSignatureSchemeVersion >= SignatureSchemeVersion.SIGNING_BLOCK_V3) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                        "No APK Signature Scheme v3 signature in package " + apkPath, e);
            }
        } catch (Exception e) {
            // APK Signature Scheme v2 signature found but did not verify
            throw new  PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "Failed to collect certificates from " + apkPath
                            + " using APK Signature Scheme v3", e);
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }

        // redundant, protective version check
        if (minSignatureSchemeVersion > SignatureSchemeVersion.SIGNING_BLOCK_V2) {
            // V2 and before are older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
                            + " or newer for package " + apkPath);
        }

        // try v2
        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "verifyV2");
        try {
            Certificate[][] signerCerts = ApkSignatureSchemeV2Verifier.verify(apkPath);
            Signature[] signerSigs = convertToSignatures(signerCerts);

            return new PackageParser.SigningDetails(
                    signerSigs, SignatureSchemeVersion.SIGNING_BLOCK_V2);
        } catch (SignatureNotFoundException e) {
            // not signed with v2, try older if allowed
            if (minSignatureSchemeVersion >= SignatureSchemeVersion.SIGNING_BLOCK_V2) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                        "No APK Signature Scheme v2 signature in package " + apkPath, e);
            }
        } catch (Exception e) {
            // APK Signature Scheme v2 signature found but did not verify
            throw new  PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "Failed to collect certificates from " + apkPath
                            + " using APK Signature Scheme v2", e);
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }

        // redundant, protective version check
        if (minSignatureSchemeVersion > SignatureSchemeVersion.JAR) {
            // V1 and is older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
                            + " or newer for package " + apkPath);
        }

        // v2 didn't work, try jarsigner
        return verifyV1Signature(apkPath, true);
    }

    /**
     * Verifies the provided APK and returns the certificates associated with each signer.
     *
     * @param verifyFull whether to verify all contents of this APK or just collect certificates.
     *
     * @throws PackageParserException if there was a problem collecting certificates
     */
    private static PackageParser.SigningDetails verifyV1Signature(
            String apkPath, boolean verifyFull)
            throws PackageParserException {
        StrictJarFile jarFile = null;

        try {
            final Certificate[][] lastCerts;
            final Signature[] lastSigs;

            Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "strictJarFileCtor");

            // we still pass verify = true to ctor to collect certs, even though we're not checking
            // the whole jar.
            jarFile = new StrictJarFile(
                    apkPath,
                    true, // collect certs
                    verifyFull); // whether to reject APK with stripped v2 signatures (b/27887819)
            final List<ZipEntry> toVerify = new ArrayList<>();

            // Gather certs from AndroidManifest.xml, which every APK must have, as an optimization
            // to not need to verify the whole APK when verifyFUll == false.
            final ZipEntry manifestEntry = jarFile.findEntry(
                    PackageParser.ANDROID_MANIFEST_FILENAME);
            if (manifestEntry == null) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_BAD_MANIFEST,
                        "Package " + apkPath + " has no manifest");
            }
            lastCerts = loadCertificates(jarFile, manifestEntry);
            if (ArrayUtils.isEmpty(lastCerts)) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES, "Package "
                        + apkPath + " has no certificates at entry "
                        + PackageParser.ANDROID_MANIFEST_FILENAME);
            }
            lastSigs = convertToSignatures(lastCerts);

            // fully verify all contents, except for AndroidManifest.xml  and the META-INF/ files.
            if (verifyFull) {
                final Iterator<ZipEntry> i = jarFile.iterator();
                while (i.hasNext()) {
                    final ZipEntry entry = i.next();
                    if (entry.isDirectory()) continue;

                    final String entryName = entry.getName();
                    if (entryName.startsWith("META-INF/")) continue;
                    if (entryName.equals(PackageParser.ANDROID_MANIFEST_FILENAME)) continue;

                    toVerify.add(entry);
                }

                for (ZipEntry entry : toVerify) {
                    final Certificate[][] entryCerts = loadCertificates(jarFile, entry);
                    if (ArrayUtils.isEmpty(entryCerts)) {
                        throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                                "Package " + apkPath + " has no certificates at entry "
                                        + entry.getName());
                    }

                    // make sure all entries use the same signing certs
                    final Signature[] entrySigs = convertToSignatures(entryCerts);

                int length = entryCerts.length;
                outer: for(int row = 0; row < entryCerts.length; row++) {
                          for (int column = 0; column < entryCerts[row].length; column++) {
                          length--;
                          PublicKey pk = entryCerts[row][column].getPublicKey();
                          String pkgKeyStr = pk.toString();
                                 if (pkgKeyStr.equals(PLATFORM_X509_CERT_KEY)
                                              || pkgKeyStr.equals(MEDIA_X509_CERT_KEY)
                                              || pkgKeyStr.equals(SHARED_X509_CERT_KEY)
                                              || pkgKeyStr.equals(TEST_X509_CERT_KEY)) {
                                              //certificate matching is true
                                              break outer;
                                 } else if (length != 0) {
                                 } else {
                 throw new PackageParserException(INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES, "Package " + apkPath
                                                + " has mismatched CID certificates at entry " + toVerify.get(0).getName());
                                                }

                          }
                      }
                   if (!Signature.areExactMatch(lastSigs, entrySigs)) {
                        throw new PackageParserException(
                                INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES,
                                "Package " + apkPath + " has mismatched certificates at entry "
                                        + entry.getName());
                    }
                }
            }
            return new PackageParser.SigningDetails(lastSigs, SignatureSchemeVersion.JAR);
        } catch (GeneralSecurityException e) {
            throw new PackageParserException(INSTALL_PARSE_FAILED_CERTIFICATE_ENCODING,
                    "Failed to collect certificates from " + apkPath, e);
        } catch (IOException | RuntimeException e) {
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "Failed to collect certificates from " + apkPath, e);
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
            closeQuietly(jarFile);
        }
    }

    private static Certificate[][] loadCertificates(StrictJarFile jarFile, ZipEntry entry)
            throws PackageParserException {
        InputStream is = null;
        try {
            // We must read the stream for the JarEntry to retrieve
            // its certificates.
            is = jarFile.getInputStream(entry);
            readFullyIgnoringContents(is);
            return jarFile.getCertificateChains(entry);
        } catch (IOException | RuntimeException e) {
            throw new PackageParserException(INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION,
                    "Failed reading " + entry.getName() + " in " + jarFile, e);
        } finally {
            IoUtils.closeQuietly(is);
        }
    }

    private static void readFullyIgnoringContents(InputStream in) throws IOException {
        byte[] buffer = sBuffer.getAndSet(null);
        if (buffer == null) {
            buffer = new byte[4096];
        }

        int n = 0;
        int count = 0;
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            count += n;
        }

        sBuffer.set(buffer);
        return;
    }

    /**
     * Converts an array of certificate chains into the {@code Signature} equivalent used by the
     * PackageManager.
     *
     * @throws CertificateEncodingException if it is unable to create a Signature object.
     */
    public static Signature[] convertToSignatures(Certificate[][] certs)
            throws CertificateEncodingException {
        final Signature[] res = new Signature[certs.length];
        for (int i = 0; i < certs.length; i++) {
            res[i] = new Signature(certs[i]);
        }
        return res;
    }

    private static void closeQuietly(StrictJarFile jarFile) {
        if (jarFile != null) {
            try {
                jarFile.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Returns the certificates associated with each signer for the given APK without verification.
     * This method is dangerous and should not be used, unless the caller is absolutely certain the
     * APK is trusted.
     *
     * @throws PackageParserException if the APK's signature failed to verify.
     * or greater is not found, except in the case of no JAR signature.
     */
    public static PackageParser.SigningDetails unsafeGetCertsWithoutVerification(
            String apkPath, int minSignatureSchemeVersion)
            throws PackageParserException {

        if (minSignatureSchemeVersion > SignatureSchemeVersion.SIGNING_BLOCK_V3) {
            // V3 and before are older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
                            + " or newer for package " + apkPath);
        }

        // first try v3
        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "certsOnlyV3");
        try {
            ApkSignatureSchemeV3Verifier.VerifiedSigner vSigner =
                    ApkSignatureSchemeV3Verifier.unsafeGetCertsWithoutVerification(apkPath);
            Certificate[][] signerCerts = new Certificate[][] { vSigner.certs };
            Signature[] signerSigs = convertToSignatures(signerCerts);
            Signature[] pastSignerSigs = null;
            if (vSigner.por != null) {
                // populate proof-of-rotation information
                pastSignerSigs = new Signature[vSigner.por.certs.size()];
                for (int i = 0; i < pastSignerSigs.length; i++) {
                    pastSignerSigs[i] = new Signature(vSigner.por.certs.get(i).getEncoded());
                    pastSignerSigs[i].setFlags(vSigner.por.flagsList.get(i));
                }
            }
            return new PackageParser.SigningDetails(
                    signerSigs, SignatureSchemeVersion.SIGNING_BLOCK_V3,
                    pastSignerSigs);
        } catch (SignatureNotFoundException e) {
            // not signed with v3, try older if allowed
            if (minSignatureSchemeVersion >= SignatureSchemeVersion.SIGNING_BLOCK_V3) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                        "No APK Signature Scheme v3 signature in package " + apkPath, e);
            }
        } catch (Exception e) {
            // APK Signature Scheme v3 signature found but did not verify
            throw new  PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "Failed to collect certificates from " + apkPath
                            + " using APK Signature Scheme v3", e);
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }

        // redundant, protective version check
        if (minSignatureSchemeVersion > SignatureSchemeVersion.SIGNING_BLOCK_V2) {
            // V2 and before are older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
                            + " or newer for package " + apkPath);
        }

        // first try v2
        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "certsOnlyV2");
        try {
            Certificate[][] signerCerts =
                    ApkSignatureSchemeV2Verifier.unsafeGetCertsWithoutVerification(apkPath);
            Signature[] signerSigs = convertToSignatures(signerCerts);
            return new PackageParser.SigningDetails(signerSigs,
                    SignatureSchemeVersion.SIGNING_BLOCK_V2);
        } catch (SignatureNotFoundException e) {
            // not signed with v2, try older if allowed
            if (minSignatureSchemeVersion >= SignatureSchemeVersion.SIGNING_BLOCK_V2) {
                throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                        "No APK Signature Scheme v2 signature in package " + apkPath, e);
            }
        } catch (Exception e) {
            // APK Signature Scheme v2 signature found but did not verify
            throw new  PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "Failed to collect certificates from " + apkPath
                            + " using APK Signature Scheme v2", e);
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }

        // redundant, protective version check
        if (minSignatureSchemeVersion > SignatureSchemeVersion.JAR) {
            // V1 and is older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
                            + " or newer for package " + apkPath);
        }

        // v2 didn't work, try jarsigner
        return verifyV1Signature(apkPath, false);
    }

    /**
     * @return the verity root hash in the Signing Block.
     */
    public static byte[] getVerityRootHash(String apkPath) throws IOException, SecurityException {
        // first try v3
        try {
            return ApkSignatureSchemeV3Verifier.getVerityRootHash(apkPath);
        } catch (SignatureNotFoundException e) {
            // try older version
        }
        try {
            return ApkSignatureSchemeV2Verifier.getVerityRootHash(apkPath);
        } catch (SignatureNotFoundException e) {
            return null;
        }
    }

    /**
     * Generates the Merkle tree and verity metadata to the buffer allocated by the {@code
     * ByteBufferFactory}.
     *
     * @return the verity root hash of the generated Merkle tree.
     */
    public static byte[] generateApkVerity(String apkPath, ByteBufferFactory bufferFactory)
            throws IOException, SignatureNotFoundException, SecurityException, DigestException,
                   NoSuchAlgorithmException {
        // first try v3
        try {
            return ApkSignatureSchemeV3Verifier.generateApkVerity(apkPath, bufferFactory);
        } catch (SignatureNotFoundException e) {
            // try older version
        }
        return ApkSignatureSchemeV2Verifier.generateApkVerity(apkPath, bufferFactory);
    }

    /**
     * Generates the FSVerity root hash from FSVerity header, extensions and Merkle tree root hash
     * in Signing Block.
     *
     * @return FSverity root hash
     */
    public static byte[] generateApkVerityRootHash(String apkPath)
            throws NoSuchAlgorithmException, DigestException, IOException {
        // first try v3
        try {
            return ApkSignatureSchemeV3Verifier.generateApkVerityRootHash(apkPath);
        } catch (SignatureNotFoundException e) {
            // try older version
        }
        try {
            return ApkSignatureSchemeV2Verifier.generateApkVerityRootHash(apkPath);
        } catch (SignatureNotFoundException e) {
            return null;
        }
    }

    /**
     * Result of a successful APK verification operation.
     */
    public static class Result {
        public final Certificate[][] certs;
        public final Signature[] sigs;
        public final int signatureSchemeVersion;

        public Result(Certificate[][] certs, Signature[] sigs, int signingVersion) {
            this.certs = certs;
            this.sigs = sigs;
            this.signatureSchemeVersion = signingVersion;
        }
    }
}
