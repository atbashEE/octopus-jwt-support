/*
 * Copyright 2017-2022 Rudy De Busscher (https://www.atbash.be)
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


import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ContentCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSACryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSA_OAEP_2;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPublicKey;


/**
 * RSA encrypter of {@link JWEObject JWE objects}. Expects a
 * public RSA key.
 *
 * <p>Encrypts the plain text with a generated AES key (the Content Encryption
 * Key) according to the specified JOSE encryption method, then encrypts the
 * CEK with the public RSA key and returns it alongside the IV, cipher text and
 * authentication tag. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.2">4.2</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.3">4.3</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#RSA_OAEP_256}
 *     <li>{@link JWEAlgorithm#RSA_OAEP_384}
 *     <li>{@link JWEAlgorithm#RSA_OAEP_512}*
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
 * Based on code by David Ortiz, Vladimir Dzhuvinov and Jun Yu
 */
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


    /**
     * The public RSA key.
     */
    private final RSAPublicKey publicKey;


    /**
     * The externally supplied AES content encryption key (CEK) to use,
     * {@code null} to generate a CEK for each JWE.
     */
    private final SecretKey contentEncryptionKey;


    /**
     * Creates a new RSA encrypter.
     *
     * @param publicKey The public RSA key. Must not be {@code null}.
     */
    public RSAEncrypter(RSAPublicKey publicKey) {

        this(publicKey, null);
    }


    /**
     * Creates a new RSA encrypter.
     *
     * @param rsaJWK The RSA JSON Web Key (JWK). Must not be {@code null}.
     *
     */
    public RSAEncrypter(RSAKey rsaJWK) {

        this(rsaJWK.toRSAPublicKey());
    }


    /**
     * Creates a new RSA encrypter with an optionally specified content
     * encryption key (CEK).
     *
     * @param publicKey            The public RSA key. Must not be
     *                             {@code null}.
     * @param contentEncryptionKey The content encryption key (CEK) to use.
     *                             If specified its algorithm must be "AES"
     *                             and its length must match the expected
     *                             for the JWE encryption method ("enc").
     *                             If {@code null} a CEK will be generated
     *                             for each JWE.
     */
    public RSAEncrypter(RSAPublicKey publicKey, SecretKey contentEncryptionKey) {

        if (publicKey == null) {
            throw new IllegalArgumentException("The public RSA key must not be null");
        }
        this.publicKey = publicKey;

        if (contentEncryptionKey != null) {
            if (contentEncryptionKey.getAlgorithm() == null || !contentEncryptionKey.getAlgorithm().equals("AES")) {
                throw new IllegalArgumentException("The algorithm of the content encryption key (CEK) must be AES");
            } else {
                this.contentEncryptionKey = contentEncryptionKey;
            }
        } else {
            this.contentEncryptionKey = null;
        }
    }


    /**
     * Gets the public RSA key.
     *
     * @return The public RSA key.
     */
    public RSAPublicKey getPublicKey() {

        return publicKey;
    }


    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) {

        JWEAlgorithm alg = header.getAlgorithm();
        EncryptionMethod enc = header.getEncryptionMethod();

        // Generate and encrypt the CEK according to the enc method
        SecretKey cek;
        if (contentEncryptionKey != null) {
            // Use externally supplied CEK
            cek = contentEncryptionKey;
        } else {
            // Generate and encrypt the CEK according to the enc method
            cek = ContentCryptoProvider.generateCEK(enc);
        }

        Base64URLValue encryptedKey; // The second JWE part


        // Encrypt the cek (used to encrypt the clearText) with the RSA public key.
        encryptedKey = Base64URLValue.encode(RSA_OAEP_2.encryptCEK(publicKey, cek, alg));


        // Define All JWE Parts
        return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey);
    }
}