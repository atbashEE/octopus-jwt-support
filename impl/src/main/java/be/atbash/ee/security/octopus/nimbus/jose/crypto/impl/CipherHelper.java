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


import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;


/**
 * Helper utilities for instantiating ciphers.
 *
 * @author Cedric Staub
 * @version 2014-01-22
 */
public final class CipherHelper {

    private CipherHelper() {
    }

    /**
     * Instantiates a cipher with an (optional) JCA provider.
     *
     * @param name     The name of the cipher. Must not be {@code null}.
     * @param provider The JCA provider, or {@code null} to use the default
     *                 one.
     */
    public static Cipher getInstance(String name, Provider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        if (provider == null) {
            return Cipher.getInstance(name);
        } else {
            return Cipher.getInstance(name, provider);
        }
    }
}
