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

import com.android.internal.util.ArrayUtils;

import libcore.io.IoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
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

    private static final String TAG = "ApkSignatureSchemeV2Verifier";
    private static final String PLATFORM_X509_CERT_KEY =
                         "OpenSSLRSAPublicKey{modulus=c1dc163b122e52f239a08616b4a35be33cc83fcdf8442a"+
                         "66eabd6704328ce158cdde5e91ffc9924f90a56eb6c3a3b3c45a9e0285a9f69b8b81ee09f3"+
                         "60c7e319e44e346b8ebd8f5277d38205845e7c1cf876e8c76e3f4a2257281d6f5cb67a5dd0"+
                         "827c90e265761aa4727c7f534d5ec1cfc20af3721a457acda81d509849a600def99686fe4f"+
                         "ba4fb559ff76969f16bc613349af3773b6ab76fc8fce20ee6be534ea11b3402c36dc8875e6"+
                         "0206f670704b7e10875d085269c4e66e1893ea664b9ea1260c277a19842cc958e7425455ab"+
                         "513368cf43f6e21b4544f26cd7041b864723fa734c5e48faa8aba3d8153a2c2aea3b0e694c"+
                         "5b54d3e88ac805a566f545,publicExponent=10001}";
    private static final String MEDIA_X509_CERT_KEY =
                         "OpenSSLRSAPublicKey{modulus=f57d73077a42576a00a75288a20a6a46e873d97e7157eb"+
                         "438a656b4385e1f717fc8794f86b9b545519358f7f2714dad52becb7dcf3766c968f8532cf"+
                         "8bb9cbfc89cf8bb8ad3ab533655a1cba2ffa3858478b10bead95b9272b3988a2ab332a85db"+
                         "e4c6b5dd187ba4288bf9339ba1122b3337e7deb005923c2e0f7638ee73b6539d3fa630fcaa"+
                         "9c974b1a4e5e600914956ba77f58b67dbad0abe787c4b8df466c57b336eef1828e118bb365"+
                         "ceb0a68d3c2a40c391d433689ebf033a69d4fb9375bba7217d18e75337fc68d053eb88102a"+
                         "65ff82846180cb3adc27be937dcec43ceab89bf13c091e3af11644f5427691450d5012355f"+
                         "f307367053e4222c7b735f,publicExponent=10001}";
    private static final String TEST_X509_CERT_KEY =
                         "OpenSSLRSAPublicKey{modulus=e7e79ce72a1064578b42d1bc890b22dc3c1d24fc8483e8"+
                         "c0f110c2b5032d52e7cd668e7c5f4f641b5a2e0e0cc618e8c16331916e2ae69c65dd55c5c1"+
                         "dc3bae0295160dc8a23ecc190857f9aa4eca649f26d0d109710eac6f2103fd410db2cbe935"+
                         "3c81c1fc20fab29249561ee07a3e0d88b5f0dabfd6ae4caa608443e9c9f726f2551102b0c4"+
                         "22c478ff88bf71833f8e9070ad7788924814a1b7abd05670787e6c41d38ffd7243d0a7ed9a"+
                         "a87ef490bf77dec205753dff37601449a992db56c7bfffd64b1862407ff6698cc1fec9229c"+
                         "eae90e465a2e0db717b0663aba9c50a36e9b147ebcae2275ac48f7cb573ce3111f36df6677"+
                         "126763619c228435045173,publicExponent=10001}";
    private static final String SHARED_X509_CERT_KEY =
                         "OpenSSLRSAPublicKey{modulus=be31b52cfb5d1274bf2b9e8b5246f8c25d743867af7c1a"+
                         "13d8b1118e991e2ea561cbf5d5a08b66facbe03e06ea3df33bd5c6bef381b96149242c3920"+
                         "3e1bda99258295eae0c363205d1aa572815315895df1a700fa9d227e68d1839038707cf0ad"+
                         "1346e2bda5085e40334646de6fb7066003894895c83c30941f52040e86a1e41a168b3f2448"+
                         "ce0e2b0a84c20fce714aeb649c83fb4edf422a710043e94216563e6781cd88f4c8c41522ea"+
                         "fbc4c8df7da5d9eec0ac56b5dd9d1e5bda1e6d31ec62425d4ae8b0a44c62d4dd08d8d4c38d"+
                         "7ee06d15fdcd7eb0635fee3d879d4b90e85d5ade9547cb0215eb85e21c501aeb1c5ac9bf60"+
                         "5064defb5cc9f291546fc7,publicExponent=10001}";

    private static final String CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=b2a5c4d00216a4b5bd4e0ab69d01a987b299e8bd90f68c6f8aa095"+
                        "1f121a3ea7e13364b04dbc9c0032107aaaeb951c6175d5648cbb8c52425aee67af7c446682988e7e73"+
                        "c89462ba3d3b368258c292c919845ddb81f7b2b87b74b6c60ef9468df0c568643eff41d884e3ac3638"+
                        "c0c2946d54aa08aa38184b4c437f7075ce6e75228955d462a37c69865fe8be85b37c908b665981f6f1"+
                        "4d515ec2a76f68b2cea826275585d91fe6716d711203433e5972a044ab184e3d8662cdde928d6b162e"+
                        "18eae1d52f1e39c9aa13e6efe24b13c49287323022af1895aee1795239ddc48d238c6aa08e615c862f"+
                        "17659d059053b3d90ea0522744b2b16829147a41235e5cda38517573827d0f59b437cf6641346b603c"+
                        "9090c0a05d66cd3a7a22f040594b25e671cfc39096905a4d69dfe1b6aa860927166e2299bafad0e3f4"+
                        "50366ddfd4afa6c57f53ae3162829a8d3ba778a46028d5f6bab07477c563f0fe6caa8796498d59d753"+
                        "962aeb84b8c563acb1f8e93a0ed17cdbafcee937a24dcc62cd666f1def8593a3e649b57f7aab817f5c"+
                        "9978d89f25c3d232419b8b802565cb74af4f959be55dbced302cd88fcdf6228e2914b0ad4b19335fbe"+
                        "6dd5e9b7e8dbf498da7a36d492cba4854aaf25ec8b1757614dc948b21d6c52fd4426f29620e50e5d58"+
                        "7bc4105efc3fa955d3045ae854250414a0a6a4c0234f762888c30ed07b1900a05791,publicExponent=10001}";
    private static final String MEDIA_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=d6931904dec60b24b1edc762e0d9d8253e3ecd6ceb1de2ff068ca8"+
                        "e8bca8cd6bd3786ea70aa76ce60ebb0f993559ffd93e77a943e7e83d4b64b8e4fea2d3e656f1e267a8"+
                        "1bbfb230b578c20443be4c7218b846f5211586f038a14e89c2be387f8ebecf8fcac3da1ee330c9ea93"+
                        "d0a7c3dc4af350220d50080732e0809717ee6a053359e6a694ec2cb3f284a0a466c87a94d83b31093a"+
                        "67372e2f6412c06e6d42f15818dffe0381cc0cd444da6cddc3b82458194801b32564134fbfde98c928"+
                        "7748dbf5676a540d8154c8bbca07b9e247553311c46b9af76fdeeccc8e69e7c8a2d08e782620943f99"+
                        "727d3c04fe72991d99df9bae38a0b2177fa31d5b6afee91f,publicExponent=3}";
    private static final String APEX_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=98d915c546e9fdb2db7866ef2aa617cf00727120e998e861ffffe5"+
                        "346610fc03140f4aba11a6735366dde1a2f4ace1aa7e862584a77490c56631499f744f4e0c07cac657"+
                        "847846919761894bc6bd0018bbef49771876c1db1308dac11678e0fdc6c3c517af81c8f666a14b8d84"+
                        "caf8a546d7b03a44de1f258eb8171ed2206e1ee87dbbdd76bbb0055d254b593d399f633d51a110a909"+
                        "9e18106baedcc207638b300c6c8d03733f60b4c31ac2c0e3676690775afebf1821d7f5e423f34c9970"+
                        "a71b6111cad5dc25e0b94b8804b477d34cfa0fd05b9581207acba75a94cb99174341670f0cbe0772dd"+
                        "0262a74b8d6b7e89eb708c64a4c959b4dd945a4f2f6864d0f81a62f8def02e57b64e76f36c1374ca1c"+
                        "73c9f6cc85dbcdb9d25c6be370d6626f73dfbb9e585275fa793a99d41c65274147640b02e2ab851565"+
                        "f16016032c246834d144b480d0a6ebee1c5d83b8734350ba40423cb6cbafbb7a8b74284b15a03999e0"+
                        "7f01a6e01556ed92c5835b8187e547d4a6334b6661e01c453e3cab7c6ba1c1b210732abe04115293df"+
                        "bdcb7ff25f3155c0f3388fec2550ea998cccbb40a3ddf912ca918324e305fdeb054a656fa08d35b52e"+
                        "e468d4b9befb4a6226ffff1a8a442f5fd1d0ac19f14b9ee50aa382986d8598c0cc89a8477fe7f66f5f"+
                        "22883c011e24bd7be0bf7ec1391cddc429a01c09378b7ed84e4c9e1384aba768e4bd,publicExponent=10001}";
    private static final String APEX_TWO_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=9c7dd4e1c2e5a1024d37eb6a7bfacffcc4bd078ba15ea2b40bdf42"+
                        "9ab7c88ae193d63391f1398d739a4b41ce380a434a8ce1fbaf1f3ad026bdbe48b97e9769a25f85d3ae"+
                        "e00bc3b3014b5106ce1d180b870e06af73f08b005bf941e8c0de009e93b9f953939051ba7f9b0c1ef4"+
                        "22459dd329584a24e201612ce0b334deb05b4dcc6936ea0b323d4f0cd90d3a65a2bb4aed45b3b6639f"+
                        "8623d2b0da5c8fb162a45348b189fab6a3780701ea66c03edbb79b43152b8e5beb82785ed3cf2aac13"+
                        "f085bea598527fb9ae53a57321404408028753595eac6a9a473223dbe6b67788522998c3477380da06"+
                        "d1d8a3600be9b90812af41d26b62418903a032b26e8363ed996a47d8f36452e6d565849f3e23b8c130"+
                        "7d26eb3add8dbb291768e01cf84789ffbb4163222fdcbb4666b34ecc4e8eb434f6861cd33f9cc25210"+
                        "30e343ba69a0f5ec6a69f40c80fc1e564c8af99c420ce8916b30c70e1bfe2d4ed9f528b4a1037f7c2f"+
                        "261501e14edb020179e4535659f71a1d8aa1cad59cd2a3b8cdd314c95a8517efc36f7873e08921272c"+
                        "e3098c41a2f492c78c8d6ad1daf774b033eb87d6cda223780e25b9ff4abb1f29b92b53ce52e735510c"+
                        "439083d966d9df7d3cc9d7a97103edb4701bda4a9947ceccc00d9bcca1bcbfeeae54975431f1b5dc3e"+
                        "209192554973613dce031d9e15d9e98b29a24325a8b6bf162177cecabfe507a224bd,publicExponent=10001}";
    private static final String APEX_THREE_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=bde084a03c1b3f6a38e458f20318e30941dad0892c350edad1462d"+
                        "52b552986d40ca7e604733ff455029557b75eef3e95e04310e4fd476f11ceb2370a9ffcd7025e18805"+
                        "b7b6f99196c26e934ae0260711f868de3e9fa58b6ae5df6af2b200da4234b99924a8fcb5cd72939760"+
                        "b63e33a80272d0464e71055406335d3fc18b1fef25f7ea6496a0927028fa7f133545a40fa15fc1e996"+
                        "3788899e821732b025daaff733bfc737e9e8db174efe4419d903c66c37a90a8a83297c74b31367fdb3"+
                        "35fbd538c7990eeb043c317b03f95b5356f22d6aca41d0b355be34c9cec1092446630336f51fdbc8e7"+
                        "200fe96c9702921b3833366417202b75b57cfd6d2251f2a878b6501a89173764a05e849588146906b4"+
                        "3fdc0c6b431390db3403b3e827520dd1365cdd107f471f375447544e9fa3616d162711455b8506df0c"+
                        "d9c6d0edbce612fb470fa5ba76c7f5db4147ee0a695ca9a784cc7559ace9c51d9096d6e26034f2d996"+
                        "62e29692fe30c17cbf603025a9dce860db2ef83467d4c39090590b03a5c922e88ed1bf00a5042c8e57"+
                        "9d4b1e7e4b13f9d8e03915ad9c643f0d3f62b4d6cf92793db74c7ad4ee22e9c4e1e738966f27667875"+
                        "113fb6307c76f91a32179bc1b38ae9d4a1c745a100bde0f601f40e5b1cfb90e1bdf9a905a2dee7f90a"+
                        "16106770634989f63b0efc82130a3bf755b0fba343a826fd51d805b9b0ad8a4383c3,publicExponent=10001}";
    private static final String APEX_FOUR_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=b73f3639c1a33bd50a5651540f7d3aed09ff4cc7dd3dec38cce919"+
                        "438da39dd85b4dee050dfddfb3d7d874591901701303587df3e1a1c80e9e185c004876a2335de86174"+
                        "214bae8e16e87e084cd71b1fafcce2b9ad1acdafd330a4aebf33fe611ab0276cc3d8b3f0b3a2ca8b86"+
                        "c60b74436a8f490dce71b652197d024fc54dc4320fd51a5075150a859b7f86c99cb8f1c6abae328a5f"+
                        "e2ec51d7e1d2e08e78a4e2c5241cfb104da9bf1ff27f6eb97d393a130b246e4e06aae847f10995573d"+
                        "fc5013a2930dc845af8c1849bc4881237dce4db03cb5c2b32bd26f69557c349b911992f3d70268202b"+
                        "17748fdc500aa1977174db53d50fca6b232cedcfe3ae1165a2222992cb4d0b332b3d3f628f943046a7"+
                        "01b1c4a28ea68424ec8ae39f0485a3bb9b718773d7bed5a7ecc53227fffbdbae9254edec0e8b0700b0"+
                        "901328614ca2d6cad5f5788c60b32b10d505dd4e3f9c8dfe23d84bc20d1f8b6dd56d50e636909ff532"+
                        "f91b92d6d3d94edacb95d8ff409fcaf57352838bf5da15e52c3c1497010cbb60246dee81608b5f85d0"+
                        "0421346bdf7da5e9ee3ae9c403a7757698e58034f117df9b39fc26b17aa24e8b763e0d2c788b08ce2a"+
                        "2a2b9a79c46a5445019ad20d4d9437122aae689d974dd8ff4a75dee81b3e625ba5714f6450cfb14baf"+
                        "3ee18b48053696e52e152813d055725a3e417f316672e2f14289b4dfe76c717f06c5,publicExponent=10001}";
    private static final String APEX_FIVE_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=dd4db3be5cd1974b2a752f12e128b73274c7238bcce1d83f7cba47"+
                        "37301723dff386800dceeb403b636e612e7fd83d429261640c5eec6d8983fc31a9ac4c5bac027e4a6e"+
                        "1255b90807235d0d22d7685156da9e3ece59e5b8f327ff02ee5b9687cd956ffb3662844fa0a3575561"+
                        "53d7a081e11327c369d6e54ca844767df0de0c8054868a569f21ce99d03226ade4d3c2512f7322a285"+
                        "5512bb37b23c6f02463b21c340b51eac6de1af09af10207cfa5df385e8e1eb5878fa55af62b9faf340"+
                        "5702e951d0f8f18eeaf6978e274b5b2fc0d2a21b9d933bd9b1052809f11fad505f66feda3e7b7a6496"+
                        "21705a3559104c61ccca3f88d66f42a0985f7adde7b7ce5894d695ed218b0d04db6131dbf2de6977d3"+
                        "5b48ec2284e40dd87af9b8d1556aa3e203b7b14dc68577aca3e19cef6f8bf62acd7ff5c4cbc0b68f04"+
                        "f40e4dbcc4ea1e64b63f4c2dd69b7d292b975e3a0801668764e0130e4548fa32e30eb60535d86a5d58"+
                        "1b01a56d23ad239516925b1cc1af8a3e8365bc92cfc980cda6c09eaa6933680ccce0f36dcc2b3cbfb7"+
                        "7f77e6cc66e46845b3d018f50cffe01ddec6a61410524b37a7492c2569a4298509d08e352c4dedb5cf"+
                        "a3eddbf4b959b8a00e3f5ecdd38f9e29cc1755e6336776bb49fc8cceaf83b4b8409ff4d296249b6c20"+
                        "1553188e667557d673341acdff0580acd13521dad4aa3b8f29c03af13f0ef3f7e9b9,publicExponent=10001}";

    private static final String APEX_SIX_CODEC_X509_CERT_KEY =
                        "OpenSSLRSAPublicKey{modulus=9cd1f3d40bec0b1544cad52b7b06424ed77dd010ded745e2e36390"+
                        "f87c10869041f0c05407373f67392371d24eee529417dcf022b34bdf0ff8dc0a355c28769a87bacc90"+
                        "4899f8777ddeb6e5a77ca6e24af8ff08b924e58311bc00d0e47c735f233fa63866b9dcb23a37ee2890"+
                        "26267c8a2083e7bf3f34d3841a1bf5b81a8500aae96855c0e24d4d1d14789d3e1f8eab1c02bad9a1a8"+
                        "765d6632f84356ee8d0d8dd8fcca9463a6e2e1b9509bd62f5297c442d40909469cf4f75fa41086567b"+
                        "3703b92ff0cc23e06554805cf421d92876e1b90c3ff6263c5a9c64d323644742ca515c33e869f4f24a"+
                        "ae8d3ebb6e0236c918e636b84f7bbb731bd697dec4b6e865,publicExponent=10001}";


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
                                              || pkgKeyStr.equals(TEST_X509_CERT_KEY)
                                              || pkgKeyStr.equals(CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(MEDIA_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_TWO_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_THREE_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_FOUR_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_FIVE_CODEC_X509_CERT_KEY)
                                              || pkgKeyStr.equals(APEX_SIX_CODEC_X509_CERT_KEY)) {
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
