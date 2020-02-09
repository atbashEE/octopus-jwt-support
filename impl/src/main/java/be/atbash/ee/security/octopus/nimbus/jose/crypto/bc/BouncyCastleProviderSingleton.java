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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.bc;


import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * BouncyCastle JCA provider singleton, intended to prevent memory leaks by
 * ensuring a single instance is loaded at all times. Application code that
 * needs a BouncyCastle JCA provider should use the {@link #getInstance()}
 * method to obtain an instance.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class BouncyCastleProviderSingleton {


    /**
     * The BouncyCastle provider, lazily instantiated.
     */
    private static BouncyCastleProvider bouncyCastleProvider;


    /**
     * Prevents external instantiation.
     */
    private BouncyCastleProviderSingleton() {
    }


    /**
     * Returns a BouncyCastle JCA provider instance.
     *
     * @return The BouncyCastle JCA provider instance.
     */
    public static synchronized BouncyCastleProvider getInstance() {

        if (bouncyCastleProvider == null) {

            bouncyCastleProvider = new BouncyCastleProvider();
        }
        return bouncyCastleProvider;
    }
}
