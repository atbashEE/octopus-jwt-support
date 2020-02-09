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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

/**
 * JSON Web Encryption (JWE) decrypter.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public interface JWEDecrypter extends JWEProvider {


    /**
     * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
     *
     * @param header       The JSON Web Encryption (JWE) header. Must
     *                     specify a supported JWE algorithm and method.
     *                     Must not be {@code null}.
     * @param encryptedKey The encrypted key, {@code null} if not required
     *                     by the JWE algorithm.
     * @param iv           The initialisation vector, {@code null} if not
     *                     required by the JWE algorithm.
     * @param cipherText   The cipher text to decrypt. Must not be
     *                     {@code null}.
     * @param authTag      The authentication tag, {@code null} if not
     *                     required.
     * @return The clear text.
     * @throws JOSEException If the JWE algorithm or method is not
     *                       supported, if a critical header parameter is
     *                       not supported or marked for deferral to the
     *                       application, or if decryption failed for some
     *                       other reason.
     */
    byte[] decrypt(JWEHeader header,
                   Base64URLValue encryptedKey,
                   Base64URLValue iv,
                   Base64URLValue cipherText,
                   Base64URLValue authTag)
            throws JOSEException;
}
