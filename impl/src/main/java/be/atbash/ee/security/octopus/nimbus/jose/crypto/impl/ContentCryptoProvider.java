/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JWEJCAContext;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.Container;
import be.atbash.ee.security.octopus.nimbus.util.IntegerOverflowException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;


/**
 * JWE content encryption / decryption provider.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-06-01
 */
public class ContentCryptoProvider {


    /**
     * The supported encryption methods.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


    /**
     * The encryption methods compatible with each key size in bits.
     */
    public static final Map<Integer, Set<EncryptionMethod>> COMPATIBLE_ENCRYPTION_METHODS;


    static {
        Set<EncryptionMethod> methods = new LinkedHashSet<>();
        methods.add(EncryptionMethod.A128CBC_HS256);
        methods.add(EncryptionMethod.A192CBC_HS384);
        methods.add(EncryptionMethod.A256CBC_HS512);
        methods.add(EncryptionMethod.A128GCM);
        methods.add(EncryptionMethod.A192GCM);
        methods.add(EncryptionMethod.A256GCM);
        SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);

        Map<Integer, Set<EncryptionMethod>> encsMap = new HashMap<>();
        Set<EncryptionMethod> bit128Encs = new HashSet<>();
        Set<EncryptionMethod> bit192Encs = new HashSet<>();
        Set<EncryptionMethod> bit256Encs = new HashSet<>();
        Set<EncryptionMethod> bit384Encs = new HashSet<>();
        Set<EncryptionMethod> bit512Encs = new HashSet<>();
        bit128Encs.add(EncryptionMethod.A128GCM);
        bit192Encs.add(EncryptionMethod.A192GCM);
        bit256Encs.add(EncryptionMethod.A256GCM);
        bit256Encs.add(EncryptionMethod.A128CBC_HS256);
        bit384Encs.add(EncryptionMethod.A192CBC_HS384);
        bit512Encs.add(EncryptionMethod.A256CBC_HS512);
        encsMap.put(128, Collections.unmodifiableSet(bit128Encs));
        encsMap.put(192, Collections.unmodifiableSet(bit192Encs));
        encsMap.put(256, Collections.unmodifiableSet(bit256Encs));
        encsMap.put(384, Collections.unmodifiableSet(bit384Encs));
        encsMap.put(512, Collections.unmodifiableSet(bit512Encs));
        COMPATIBLE_ENCRYPTION_METHODS = Collections.unmodifiableMap(encsMap);
    }


    /**
     * Generates a Content Encryption Key (CEK) for the specified JOSE
     * encryption method.
     *
     * @param enc       The encryption method. Must not be {@code null}.
     * @param randomGen The secure random generator to use. Must not be
     *                  {@code null}.
     * @return The generated CEK (with algorithm "AES").
     * @throws JOSEException If the encryption method is not supported.
     */
    public static SecretKey generateCEK(EncryptionMethod enc, SecureRandom randomGen)
            throws JOSEException {

        if (!SUPPORTED_ENCRYPTION_METHODS.contains(enc)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(enc, SUPPORTED_ENCRYPTION_METHODS));
        }

        byte[] cekMaterial = new byte[ByteUtils.byteLength(enc.cekBitLength())];

        randomGen.nextBytes(cekMaterial);

        return new SecretKeySpec(cekMaterial, "AES");
    }


    /**
     * Checks the length of the Content Encryption Key (CEK) according to
     * the encryption method.
     *
     * @param cek The CEK. Must not be {@code null}.
     * @param enc The encryption method. Must not be {@code null}.
     * @throws KeyLengthException If the CEK length doesn't match the
     *                            encryption method.
     */
    private static void checkCEKLength(SecretKey cek, EncryptionMethod enc)
            throws KeyLengthException {

        try {
            if (enc.cekBitLength() != ByteUtils.safeBitLength(cek.getEncoded())) {
                throw new KeyLengthException("The Content Encryption Key (CEK) length for " + enc + " must be " + enc.cekBitLength() + " bits");
            }
        } catch (IntegerOverflowException e) {
            throw new KeyLengthException("The Content Encryption Key (CEK) is too long: " + e.getMessage());
        }
    }


    /**
     * Encrypts the specified clear text (content).
     *
     * @param header       The final JWE header. Must not be {@code null}.
     * @param clearText    The clear text to encrypt and optionally
     *                     compress. Must not be {@code null}.
     * @param cek          The Content Encryption Key (CEK). Must not be
     *                     {@code null}.
     * @param encryptedKey The encrypted CEK, {@code null} if not required.
     * @param jcaProvider  The JWE JCA provider specification. Must not be
     *                     {@code null}.
     * @return The JWE crypto parts.
     * @throws JOSEException If encryption failed.
     */
    public static JWECryptoParts encrypt(JWEHeader header,
                                         byte[] clearText,
                                         SecretKey cek,
                                         Base64URLValue encryptedKey,
                                         JWEJCAContext jcaProvider)
            throws JOSEException {

        checkCEKLength(cek, header.getEncryptionMethod());

        // Apply compression if instructed
        byte[] plainText = DeflateHelper.applyCompression(header, clearText);

        // Compose the AAD
        byte[] aad = AAD.compute(header);

        // Encrypt the plain text according to the JWE enc
        byte[] iv;
        AuthenticatedCipherText authCipherText;

        if (header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A192CBC_HS384) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512)) {

            iv = AESCBC.generateIV(jcaProvider.getSecureRandom());

            authCipherText = AESCBC.encryptAuthenticated(
                    cek, iv, plainText, aad,
                    jcaProvider.getContentEncryptionProvider(),
                    jcaProvider.getMACProvider());

        } else if (header.getEncryptionMethod().equals(EncryptionMethod.A128GCM) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A192GCM) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A256GCM)) {

            Container<byte[]> ivContainer = new Container<>(AESGCM.generateIV(jcaProvider.getSecureRandom()));

            authCipherText = AESGCM.encrypt(
                    cek, ivContainer, plainText, aad,
                    jcaProvider.getContentEncryptionProvider());

            iv = ivContainer.get();

        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(
                    header.getEncryptionMethod(),
                    SUPPORTED_ENCRYPTION_METHODS));
        }

        return new JWECryptoParts(
                header,
                encryptedKey,
                Base64URLValue.encode(iv),
                Base64URLValue.encode(authCipherText.getCipherText()),
                Base64URLValue.encode(authCipherText.getAuthenticationTag()));
    }


    /**
     * Decrypts the specified cipher text.
     *
     * @param header       The JWE header. Must not be {@code null}.
     * @param encryptedKey The encrypted key, {@code null} if not
     *                     specified.
     * @param iv           The initialisation vector (IV). Must not be
     *                     {@code null}.
     * @param cipherText   The cipher text. Must not be {@code null}.
     * @param authTag      The authentication tag. Must not be
     *                     {@code null}.
     * @param cek          The Content Encryption Key (CEK). Must not be
     *                     {@code null}.
     * @param jcaProvider  The JWE JCA provider specification. Must not be
     *                     {@code null}.
     * @return The clear text.
     * @throws JOSEException If decryption failed.
     */
    public static byte[] decrypt(JWEHeader header,
                                 Base64URLValue encryptedKey,
                                 Base64URLValue iv,
                                 Base64URLValue cipherText,
                                 Base64URLValue authTag,
                                 SecretKey cek,
                                 JWEJCAContext jcaProvider)
            throws JOSEException {

        checkCEKLength(cek, header.getEncryptionMethod());

        // Compose the AAD
        byte[] aad = AAD.compute(header);

        // Decrypt the cipher text according to the JWE enc

        byte[] plainText;

        if (header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A192CBC_HS384) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512)) {

            plainText = AESCBC.decryptAuthenticated(
                    cek,
                    iv.decode(),
                    cipherText.decode(),
                    aad,
                    authTag.decode(),
                    jcaProvider.getContentEncryptionProvider(),
                    jcaProvider.getMACProvider());

        } else if (header.getEncryptionMethod().equals(EncryptionMethod.A128GCM) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A192GCM) ||
                header.getEncryptionMethod().equals(EncryptionMethod.A256GCM)) {

            plainText = AESGCM.decrypt(
                    cek,
                    iv.decode(),
                    cipherText.decode(),
                    aad,
                    authTag.decode(),
                    jcaProvider.getContentEncryptionProvider());

        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(
                    header.getEncryptionMethod(),
                    SUPPORTED_ENCRYPTION_METHODS));
        }


        // Apply decompression if requested
        return DeflateHelper.applyDecompression(header, plainText);
    }
}
