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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


/**
 * Static methods for Hash-based Message Authentication Codes (HMAC). This
 * class is thread-safe.
 *
 * Based on code by Axel Nennker and Vladimir Dzhuvinov
 */
public final class HMAC {

    private HMAC() {
    }

    public static Mac getInitMac(SecretKey secretKey) {

        Mac mac;

        try {

            mac = Mac.getInstance(secretKey.getAlgorithm(), BouncyCastleProviderSingleton.getInstance());

            mac.init(secretKey);

        } catch (NoSuchAlgorithmException e) {

            throw new JOSEException("Unsupported HMAC algorithm: " + e.getMessage(), e);

        } catch (InvalidKeyException e) {

            throw new JOSEException("Invalid HMAC key: " + e.getMessage(), e);
        }

        return mac;
    }


    /**
     * Computes a Hash-based Message Authentication Code (HMAC) for the
     * specified secret and message.
     *
     * @param alg      The Java Cryptography Architecture (JCA) HMAC
     *                 algorithm name. Must not be {@code null}.
     * @param secret   The secret. Must not be {@code null}.
     * @param message  The message. Must not be {@code null}.
     * @return A MAC service instance.
     */
    public static byte[] compute(String alg,
                                 byte[] secret,
                                 byte[] message) {

        return compute(new SecretKeySpec(secret, alg), message);
    }


    /**
     * Computes a Hash-based Message Authentication Code (HMAC) for the
     * specified secret key and message.
     *
     * @param secretKey The secret key, with the appropriate HMAC
     *                  algorithm. Must not be {@code null}.
     * @param message   The message. Must not be {@code null}.
     * @return A MAC service instance.
     */
    public static byte[] compute(SecretKey secretKey,
                                 byte[] message) {

        Mac mac = getInitMac(secretKey);
        mac.update(message);
        return mac.doFinal();
    }
}
