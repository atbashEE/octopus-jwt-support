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


import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;


/**
 * Helper utilities for instantiating ciphers.
 *
 * Based on code by Cedric Staub
 */
public final class CipherHelper {

    private CipherHelper() {
    }

    /**
     * Instantiates a cipher.
     *
     * @param name The name of the cipher. Must not be {@code null}.
     */
    public static Cipher getInstance(String name)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        return Cipher.getInstance(name, BouncyCastleProviderSingleton.getInstance());

    }
}
