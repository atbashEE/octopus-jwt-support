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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.util.KeyUtils;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * AES key Wrapping methods for Content Encryption Key (CEK) encryption and
 * decryption. This class is thread-safe.
 *
 * <p>See RFC 7518 (JWA), section 4.4.
 *
 * Based on code by Melisa Halsband and Vladimir Dzhuvinov
 */
public final class AESKW {


    /**
     * Wraps the specified Content Encryption Key (CEK).
     *
     * @param cek The Content Encryption Key (CEK) to wrap. Must not
     *            be {@code null}.
     * @param kek The AES Key Encryption Key (KEK) (wrapping key).
     *            Must not be {@code null}.
     * @return The wrapped Content Encryption Key (CEK).
     */
    public static byte[] wrapCEK(SecretKey cek,
                                 SecretKey kek) {

        try {
            Cipher cipher = Cipher.getInstance("AESWrap", BouncyCastleProviderSingleton.getInstance());

            cipher.init(Cipher.WRAP_MODE, kek);
            return cipher.wrap(cek);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new JOSEException("Couldn't wrap AES key: " + e.getMessage(), e);
        }
    }


    /**
     * Unwraps the specified encrypted Content Encryption Key (CEK).
     *
     * @param kek          The AES Key Encryption Key (KEK) (wrapping key).
     *                     Must not be {@code null}.
     * @param encryptedCEK The wrapped Content Encryption Key (CEK) with
     *                     authentication tag. Must not be {@code null}.
     * @return The unwrapped Content Encryption Key (CEK).
     */
    public static SecretKey unwrapCEK(SecretKey kek,
                                      byte[] encryptedCEK) {

        try {
            Cipher cipher = Cipher.getInstance("AESWrap", BouncyCastleProviderSingleton.getInstance());

            cipher.init(Cipher.UNWRAP_MODE, KeyUtils.toAESKey(kek)); // Make sure key alg is "AES"
            return (SecretKey) cipher.unwrap(encryptedCEK, "AES", Cipher.SECRET_KEY);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {

            throw new JOSEException("Couldn't unwrap AES key: " + e.getMessage(), e);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private AESKW() {
    }
}