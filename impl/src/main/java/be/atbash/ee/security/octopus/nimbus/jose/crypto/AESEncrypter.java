/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.*;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.Container;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * AES and AES GCM key wrap encrypter of {@link JWEObject JWE
 * objects}. Expects an AES key.
 *
 * <p>Encrypts the plain text with a generated AES key (the Content Encryption
 * Key) according to the specified JOSE encryption method, then wraps the CEK
 * with the specified AES key and returns it alongside the IV, cipher text and
 * authentication tag. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.4">4.4</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.7">4.7</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#A128KW}
 *     <li>{@link JWEAlgorithm#A192KW}
 *     <li>{@link JWEAlgorithm#A256KW}
 *     <li>{@link JWEAlgorithm#A128GCMKW}
 *     <li>{@link JWEAlgorithm#A192GCMKW}
 *     <li>{@link JWEAlgorithm#A256GCMKW}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link EncryptionMethod#A128CBC_HS256}
 *     <li>{@link EncryptionMethod#A192CBC_HS384}
 *     <li>{@link EncryptionMethod#A256CBC_HS512}
 *     <li>{@link EncryptionMethod#A128GCM}
 *     <li>{@link EncryptionMethod#A192GCM}
 *     <li>{@link EncryptionMethod#A256GCM}
 * </ul>
 *
 * Based on code by Melisa Halsband, Vladimir Dzhuvinov and Dimitar A. Stoikov
 */
public class AESEncrypter extends AESCryptoProvider implements JWEEncrypter {


    /**
     * Algorithm family constants.
     */
    private enum AlgFamily {

        AESKW, AESGCMKW
    }


    /**
     * Creates a new AES encrypter.
     *
     * @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192
     *            bits (24 bytes) or 256 bits (32 bytes). Must not be
     *            {@code null}.
     */
    public AESEncrypter(SecretKey kek) {

        super(kek);
    }

    /**
     * Creates a new AES encrypter.
     *
     * @param keyBytes The Key Encryption Key, as a byte array. Must be 128
     *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
     *                 bytes). Must not be {@code null}.
     */
    public AESEncrypter(byte[] keyBytes) {

        this(new SecretKeySpec(keyBytes, "AES"));
    }


    /**
     * Creates a new AES encrypter.
     *
     * @param octJWK The Key Encryption Key, as a JWK. Must be 128 bits (16
     *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
     *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
     *               be {@code null}.
     */
    public AESEncrypter(OctetSequenceKey octJWK) {

        this(octJWK.toSecretKey());
    }


    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) {

        JWEAlgorithm alg = header.getAlgorithm();

        // Check the AES key size and determine the algorithm family
        AlgFamily algFamily;

        if (alg.equals(JWEAlgorithm.A128KW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 128) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 128 bits for A128KW encryption");
            }
            algFamily = AlgFamily.AESKW;

        } else if (alg.equals(JWEAlgorithm.A192KW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 192) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 192 bits for A192KW encryption");
            }
            algFamily = AlgFamily.AESKW;

        } else if (alg.equals(JWEAlgorithm.A256KW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 256) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 256 bits for A256KW encryption");
            }
            algFamily = AlgFamily.AESKW;

        } else if (alg.equals(JWEAlgorithm.A128GCMKW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 128) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 128 bits for A128GCMKW encryption");
            }
            algFamily = AlgFamily.AESGCMKW;

        } else if (alg.equals(JWEAlgorithm.A192GCMKW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 192) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 192 bits for A192GCMKW encryption");
            }
            algFamily = AlgFamily.AESGCMKW;

        } else if (alg.equals(JWEAlgorithm.A256GCMKW)) {

            if (ByteUtils.safeBitLength(getKey().getEncoded()) != 256) {
                throw new KeyLengthException("The Key Encryption Key (KEK) length must be 256 bits for A256GCMKW encryption");
            }
            algFamily = AlgFamily.AESGCMKW;

        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }


        JWEHeader updatedHeader; // We need to work on the header
        Base64URLValue encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        EncryptionMethod enc = header.getEncryptionMethod();
        SecretKey cek = ContentCryptoProvider.generateCEK(enc);

        if (AlgFamily.AESKW.equals(algFamily)) {

            encryptedKey = Base64URLValue.encode(AESKW.wrapCEK(cek, getKey()));
            updatedHeader = header; // simply copy ref

        } else if (AlgFamily.AESGCMKW.equals(algFamily)) {

            Container<byte[]> keyIV = new Container<>(AESGCM.generateIV());
            AuthenticatedCipherText authCiphCEK = AESGCMKW.encryptCEK(cek, keyIV, getKey());
            encryptedKey = Base64URLValue.encode(authCiphCEK.getCipherText());

            // Add iv and tag to the header
            updatedHeader = new JWEHeader.Builder(header).
                    iv(Base64URLValue.encode(keyIV.get())).
                    authTag(Base64URLValue.encode(authCiphCEK.getAuthenticationTag())).
                    build();
        } else {
            // This should never happen
            throw new JOSEException("Unexpected JWE algorithm: " + alg);
        }

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey);
    }
}