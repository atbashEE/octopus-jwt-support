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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object. This class is
 * an immutable wrapper for returning the cipher text, initialisation vector
 * (IV), encrypted key and authentication authTag from {@link JWEEncrypter}
 * implementations.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-11
 */
public final class JWECryptoParts {


    /**
     * The modified JWE header (optional).
     */
    private final JWEHeader header;


    /**
     * The encrypted key (optional).
     */
    private final Base64URLValue encryptedKey;


    /**
     * The initialisation vector (optional).
     */
    private final Base64URLValue iv;


    /**
     * The cipher text.
     */
    private final Base64URLValue cipherText;


    /**
     * The authentication tag (optional).
     */
    private final Base64URLValue authenticationTag;


    /**
     * Creates a new cryptographic JWE parts instance.
     *
     * @param encryptedKey      The encrypted key, {@code null} if not
     *                          required by the encryption algorithm.
     * @param iv                The initialisation vector (IV),
     *                          {@code null} if not required by the
     *                          encryption algorithm.
     * @param cipherText        The cipher text. Must not be {@code null}.
     * @param authenticationTag The authentication tag, {@code null} if the
     *                          JWE algorithm provides built-in integrity
     *                          check.
     */
    public JWECryptoParts(Base64URLValue encryptedKey,
                          Base64URLValue iv,
                          Base64URLValue cipherText,
                          Base64URLValue authenticationTag) {

        this(null, encryptedKey, iv, cipherText, authenticationTag);
    }


    /**
     * Creates a new cryptographic JWE parts instance.
     *
     * @param header            The modified JWE header, {@code null} if
     *                          not.
     * @param encryptedKey      The encrypted key, {@code null} if not
     *                          required by the encryption algorithm.
     * @param iv                The initialisation vector (IV),
     *                          {@code null} if not required by the
     *                          encryption algorithm.
     * @param cipherText        The cipher text. Must not be {@code null}.
     * @param authenticationTag The authentication tag, {@code null} if the
     *                          JWE algorithm provides built-in integrity
     *                          check.
     */
    public JWECryptoParts(JWEHeader header,
                          Base64URLValue encryptedKey,
                          Base64URLValue iv,
                          Base64URLValue cipherText,
                          Base64URLValue authenticationTag) {

        this.header = header;

        this.encryptedKey = encryptedKey;

        this.iv = iv;

        if (cipherText == null) {

            throw new IllegalArgumentException("The cipher text must not be null");
        }

        this.cipherText = cipherText;

        this.authenticationTag = authenticationTag;
    }


    /**
     * Gets the modified JWE header.
     *
     * @return The modified JWE header, {@code null} of not.
     */
    public JWEHeader getHeader() {

        return header;
    }


    /**
     * Gets the encrypted key.
     *
     * @return The encrypted key, {@code null} if not required by
     * the JWE algorithm.
     */
    public Base64URLValue getEncryptedKey() {

        return encryptedKey;
    }


    /**
     * Gets the initialisation vector (IV).
     *
     * @return The initialisation vector (IV), {@code null} if not required
     * by the JWE algorithm.
     */
    public Base64URLValue getInitializationVector() {

        return iv;
    }


    /**
     * Gets the cipher text.
     *
     * @return The cipher text.
     */
    public Base64URLValue getCipherText() {

        return cipherText;
    }


    /**
     * Gets the authentication tag.
     *
     * @return The authentication tag, {@code null} if the encryption
     * algorithm provides built-in integrity checking.
     */
    public Base64URLValue getAuthenticationTag() {

        return authenticationTag;
    }
}
