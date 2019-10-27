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
package be.atbash.ee.security.octopus.nimbus.util;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * JCA key utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-02-11
 */
public final class KeyUtils {


    /**
     * Returns the specified secret key as a secret key with its algorithm
     * set to "AES".
     *
     * @param secretKey The secret key, {@code null} if not specified.
     * @return The AES secret key, {@code null} if not specified.
     */
    public static SecretKey toAESKey(final SecretKey secretKey) {

        if (secretKey == null) {
            return null;
        }

        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }


    /**
     * Prevents public instantiation.
     */
    private KeyUtils() {
    }
}
