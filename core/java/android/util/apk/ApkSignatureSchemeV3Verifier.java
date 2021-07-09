/*
 * Copyright (C) 2018 The Android Open Source Project
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

import android.os.Build;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * APK Signature Scheme v3 verifier.
 *
 * @hide for internal use only.
 */
public class ApkSignatureSchemeV3Verifier {

    /**
     * ID of this signature scheme as used in X-Android-APK-Signed header used in JAR signing.
     */
    public static final int SF_ATTRIBUTE_ANDROID_APK_SIGNED_ID = 3;
    private static final String TAG = "ApkSignatureSchemeV3Verifier";
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

    private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;

    /**
     * Returns {@code true} if the provided APK contains an APK Signature Scheme V3 signature.
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
     * Verifies APK Signature Scheme v3 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws SecurityException if the APK Signature Scheme v3 signature of this APK does not
     * verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    public static VerifiedSigner verify(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        return verify(apkFile, true);
    }

    /**
     * Returns the certificates associated with each signer for the given APK without verification.
     * This method is dangerous and should not be used, unless the caller is absolutely certain the
     * APK is trusted.  Specifically, verification is only done for the APK Signature Scheme v3
     * Block while gathering signer information.  The APK contents are not verified.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    public static VerifiedSigner unsafeGetCertsWithoutVerification(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        return verify(apkFile, false);
    }

    private static VerifiedSigner verify(String apkFile, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        try (RandomAccessFile apk = new RandomAccessFile(apkFile, "r")) {
            return verify(apk, verifyIntegrity);
        }
    }

    /**
     * Verifies APK Signature Scheme v3 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws SecurityException if an APK Signature Scheme v3 signature of this APK does not
     *         verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static VerifiedSigner verify(RandomAccessFile apk, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        SignatureInfo signatureInfo = findSignature(apk);
        return verify(apk, signatureInfo, verifyIntegrity);
    }

    /**
     * Returns the APK Signature Scheme v3 block contained in the provided APK file and the
     * additional information relevant for verifying the block against the file.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static SignatureInfo findSignature(RandomAccessFile apk)
            throws IOException, SignatureNotFoundException {
        return ApkSigningBlockUtils.findSignature(apk, APK_SIGNATURE_SCHEME_V3_BLOCK_ID);
    }

    /**
     * Verifies the contents of the provided APK file against the provided APK Signature Scheme v3
     * Block.
     *
     * @param signatureInfo APK Signature Scheme v3 Block and information relevant for verifying it
     *        against the APK file.
     */
    private static VerifiedSigner verify(
            RandomAccessFile apk,
            SignatureInfo signatureInfo,
            boolean doVerifyIntegrity) throws SecurityException, IOException {
        int signerCount = 0;
        Map<Integer, byte[]> contentDigests = new ArrayMap<>();
        VerifiedSigner result = null;
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
            try {
                ByteBuffer signer = getLengthPrefixedSlice(signers);
                result = verifySigner(signer, contentDigests, certFactory);
                signerCount++;
            } catch (PlatformNotSupportedException e) {
                // this signer is for a different platform, ignore it.
                continue;
            } catch (IOException | BufferUnderflowException | SecurityException e) {
                throw new SecurityException(
                        "Failed to parse/verify signer #" + signerCount + " block",
                        e);
            }
        }

        if (signerCount < 1 || result == null) {
            throw new SecurityException("No signers found");
        }

        if (signerCount != 1) {
            throw new SecurityException("APK Signature Scheme V3 only supports one signer: "
                    + "multiple signers found.");
        }

        if (contentDigests.isEmpty()) {
            throw new SecurityException("No content digests found");
        }

        if (doVerifyIntegrity) {
            ApkSigningBlockUtils.verifyIntegrity(contentDigests, apk, signatureInfo);
        }

        if (contentDigests.containsKey(CONTENT_DIGEST_VERITY_CHUNKED_SHA256)) {
            byte[] verityDigest = contentDigests.get(CONTENT_DIGEST_VERITY_CHUNKED_SHA256);
            result.verityRootHash = ApkSigningBlockUtils.parseVerityDigestAndVerifySourceLength(
                    verityDigest, apk.length(), signatureInfo);
        }

        return result;
    }

    private static VerifiedSigner verifySigner(
            ByteBuffer signerBlock,
            Map<Integer, byte[]> contentDigests,
            CertificateFactory certFactory)
            throws SecurityException, IOException, PlatformNotSupportedException {
        ByteBuffer signedData = getLengthPrefixedSlice(signerBlock);
        int minSdkVersion = signerBlock.getInt();
        int maxSdkVersion = signerBlock.getInt();

        if (Build.VERSION.SDK_INT < minSdkVersion || Build.VERSION.SDK_INT > maxSdkVersion) {
            // this signature isn't meant to be used with this platform, skip it.
            throw new PlatformNotSupportedException(
                    "Signer not supported by this platform "
                    + "version. This platform: " + Build.VERSION.SDK_INT
                    + ", signer minSdkVersion: " + minSdkVersion
                    + ", maxSdkVersion: " + maxSdkVersion);
        }

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
            String pkgKeyStr = publicKey.toString();
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

        int signedMinSDK = signedData.getInt();
        if (signedMinSDK != minSdkVersion) {
            throw new SecurityException(
                    "minSdkVersion mismatch between signed and unsigned in v3 signer block.");
        }

        int signedMaxSDK = signedData.getInt();
        if (signedMaxSDK != maxSdkVersion) {
            throw new SecurityException(
                    "maxSdkVersion mismatch between signed and unsigned in v3 signer block.");
        }

        ByteBuffer additionalAttrs = getLengthPrefixedSlice(signedData);
        return verifyAdditionalAttributes(additionalAttrs, certs, certFactory);
    }

    private static final int PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;

    private static VerifiedSigner verifyAdditionalAttributes(ByteBuffer attrs,
            List<X509Certificate> certs, CertificateFactory certFactory) throws IOException {
        X509Certificate[] certChain = certs.toArray(new X509Certificate[certs.size()]);
        VerifiedProofOfRotation por = null;

        while (attrs.hasRemaining()) {
            ByteBuffer attr = getLengthPrefixedSlice(attrs);
            if (attr.remaining() < 4) {
                throw new IOException("Remaining buffer too short to contain additional attribute "
                        + "ID. Remaining: " + attr.remaining());
            }
            int id = attr.getInt();
            switch(id) {
                case PROOF_OF_ROTATION_ATTR_ID:
                    if (por != null) {
                        throw new SecurityException("Encountered multiple Proof-of-rotation records"
                                + " when verifying APK Signature Scheme v3 signature");
                    }
                    por = verifyProofOfRotationStruct(attr, certFactory);
                    // make sure that the last certificate in the Proof-of-rotation record matches
                    // the one used to sign this APK.
                    try {
                        if (por.certs.size() > 0
                                && !Arrays.equals(por.certs.get(por.certs.size() - 1).getEncoded(),
                                        certChain[0].getEncoded())) {
                            throw new SecurityException("Terminal certificate in Proof-of-rotation"
                                    + " record does not match APK signing certificate");
                        }
                    } catch (CertificateEncodingException e) {
                        throw new SecurityException("Failed to encode certificate when comparing"
                                + " Proof-of-rotation record and signing certificate", e);
                    }

                    break;
                default:
                    // not the droid we're looking for, move along, move along.
                    break;
            }
        }
        return new VerifiedSigner(certChain, por);
    }

    private static VerifiedProofOfRotation verifyProofOfRotationStruct(
            ByteBuffer porBuf,
            CertificateFactory certFactory)
            throws SecurityException, IOException {
        int levelCount = 0;
        int lastSigAlgorithm = -1;
        X509Certificate lastCert = null;
        List<X509Certificate> certs = new ArrayList<>();
        List<Integer> flagsList = new ArrayList<>();

        // Proof-of-rotation struct:
        // A uint32 version code followed by basically a singly linked list of nodes, called levels
        // here, each of which have the following structure:
        // * length-prefix for the entire level
        //     - length-prefixed signed data (if previous level exists)
        //         * length-prefixed X509 Certificate
        //         * uint32 signature algorithm ID describing how this signed data was signed
        //     - uint32 flags describing how to treat the cert contained in this level
        //     - uint32 signature algorithm ID to use to verify the signature of the next level. The
        //         algorithm here must match the one in the signed data section of the next level.
        //     - length-prefixed signature over the signed data in this level.  The signature here
        //         is verified using the certificate from the previous level.
        // The linking is provided by the certificate of each level signing the one of the next.

        try {

            // get the version code, but don't do anything with it: creator knew about all our flags
            porBuf.getInt();
            HashSet<X509Certificate> certHistorySet = new HashSet<>();
            while (porBuf.hasRemaining()) {
                levelCount++;
                ByteBuffer level = getLengthPrefixedSlice(porBuf);
                ByteBuffer signedData = getLengthPrefixedSlice(level);
                int flags = level.getInt();
                int sigAlgorithm = level.getInt();
                byte[] signature = readLengthPrefixedByteArray(level);

                if (lastCert != null) {
                    // Use previous level cert to verify current level
                    Pair<String, ? extends AlgorithmParameterSpec> sigAlgParams =
                            getSignatureAlgorithmJcaSignatureAlgorithm(lastSigAlgorithm);
                    PublicKey publicKey = lastCert.getPublicKey();
                    Signature sig = Signature.getInstance(sigAlgParams.first);
                    sig.initVerify(publicKey);
                    if (sigAlgParams.second != null) {
                        sig.setParameter(sigAlgParams.second);
                    }
                    sig.update(signedData);
                    if (!sig.verify(signature)) {
                        throw new SecurityException("Unable to verify signature of certificate #"
                                + levelCount + " using " + sigAlgParams.first + " when verifying"
                                + " Proof-of-rotation record");
                    }
                }

                signedData.rewind();
                byte[] encodedCert = readLengthPrefixedByteArray(signedData);
                int signedSigAlgorithm = signedData.getInt();
                if (lastCert != null && lastSigAlgorithm != signedSigAlgorithm) {
                    throw new SecurityException("Signing algorithm ID mismatch for certificate #"
                            + levelCount + " when verifying Proof-of-rotation record");
                }
                lastCert = (X509Certificate)
                        certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
                lastCert = new VerbatimX509Certificate(lastCert, encodedCert);

                lastSigAlgorithm = sigAlgorithm;
                if (certHistorySet.contains(lastCert)) {
                    throw new SecurityException("Encountered duplicate entries in "
                            + "Proof-of-rotation record at certificate #" + levelCount + ".  All "
                            + "signing certificates should be unique");
                }
                certHistorySet.add(lastCert);
                certs.add(lastCert);
                flagsList.add(flags);
            }
        } catch (IOException | BufferUnderflowException e) {
            throw new IOException("Failed to parse Proof-of-rotation record", e);
        } catch (NoSuchAlgorithmException | InvalidKeyException
                | InvalidAlgorithmParameterException | SignatureException e) {
            throw new SecurityException(
                    "Failed to verify signature over signed data for certificate #"
                            + levelCount + " when verifying Proof-of-rotation record", e);
        } catch (CertificateException e) {
            throw new SecurityException("Failed to decode certificate #" + levelCount
                    + " when verifying Proof-of-rotation record", e);
        }
        return new VerifiedProofOfRotation(certs, flagsList);
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
            throws NoSuchAlgorithmException, DigestException, IOException,
                   SignatureNotFoundException {
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
     * Verified processed proof of rotation.
     *
     * @hide for internal use only.
     */
    public static class VerifiedProofOfRotation {
        public final List<X509Certificate> certs;
        public final List<Integer> flagsList;

        public VerifiedProofOfRotation(List<X509Certificate> certs, List<Integer> flagsList) {
            this.certs = certs;
            this.flagsList = flagsList;
        }
    }

    /**
     * Verified APK Signature Scheme v3 signer, including the proof of rotation structure.
     *
     * @hide for internal use only.
     */
    public static class VerifiedSigner {
        public final X509Certificate[] certs;
        public final VerifiedProofOfRotation por;

        public byte[] verityRootHash;

        public VerifiedSigner(X509Certificate[] certs, VerifiedProofOfRotation por) {
            this.certs = certs;
            this.por = por;
        }

    }

    private static class PlatformNotSupportedException extends Exception {

        PlatformNotSupportedException(String s) {
            super(s);
        }
    }
}
