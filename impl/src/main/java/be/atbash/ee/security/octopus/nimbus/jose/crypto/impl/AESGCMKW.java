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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;

import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.Container;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES GCM methods for Content Encryption Key (CEK) encryption and
 * decryption. This class is thread-safe.
 *
 * <p>See RFC 7518 (JWA), section 4.7.
 *
 * Based on code by Melisa Halsband and Vladimir Dzhuvinov
 */
public final class AESGCMKW {

    /**
     * Encrypts the specified Content Encryption Key (CEK).
     *
     * @param cek      The Content Encryption Key (CEK) to encrypt. Must
     *                 not be {@code null}.
     * @param iv       The initialisation vector (IV). Must not be
     *                 {@code null}. The contained IV must not be
     *                 {@code null} either.
     * @param kek      The AES Key Encryption Key (KEK). Must not be
     *                 {@code null}.
     * @return The encrypted Content Encryption Key (CEK).
     * @throws JOSEException If encryption failed.
     */
    public static AuthenticatedCipherText encryptCEK(SecretKey cek,
                                                     Container<byte[]> iv,
                                                     SecretKey kek)
            throws JOSEException {

        return AESGCM.encrypt(kek, iv, cek.getEncoded(), new byte[0]);
    }


    /**
     * Decrypts the specified encrypted Content Encryption Key (CEK).
     *
     * @param kek         The AES Key Encription Key. Must not be
     *                    {@code null}.
     * @param iv          The initialisation vector (IV). Must not be
     *                    {@code null}.
     * @param authEncrCEK The encrypted Content Encryption Key (CEK) to
     *                    decrypt and authentication tag. Must not be
     *                    {@code null}.
     * @return The decrypted Content Encryption Key (CEK).
     * @throws JOSEException If decryption failed.
     */
    public static SecretKey decryptCEK(SecretKey kek,
                                       byte[] iv,
                                       AuthenticatedCipherText authEncrCEK,
                                       int keyLength)
            throws JOSEException {

        byte[] keyBytes = AESGCM.decrypt(kek, iv, authEncrCEK.getCipherText(), new byte[0], authEncrCEK.getAuthenticationTag());

        if (ByteUtils.safeBitLength(keyBytes) != keyLength) {

            throw new KeyLengthException("CEK key length mismatch: " + ByteUtils.safeBitLength(keyBytes) + " != " + keyLength);
        }

        return new SecretKeySpec(keyBytes, "AES");
    }


    /**
     * Prevents public instantiation.
     */
    private AESGCMKW() {
    }
}