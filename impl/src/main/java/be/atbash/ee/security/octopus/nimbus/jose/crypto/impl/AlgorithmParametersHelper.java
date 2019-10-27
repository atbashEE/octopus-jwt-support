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


import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;


/**
 * Utility for creating {@link AlgorithmParameters} objects with
 * an optional JCA provider.
 *
 * @author Justin Richer
 */
public class AlgorithmParametersHelper {


    /**
     * Creates a new {@link AlgorithmParameters} instance.
     *
     * @param name     The name of the requested algorithm. Must not be
     *                 {@code null}.
     * @param provider The JCA provider, or {@code null} to use the default
     *                 one.
     * @return The AlgorithmParameters instance.
     * @throws NoSuchAlgorithmException If an AlgorithmParameterGeneratorSpi
     *                                  implementation for the specified
     *                                  algorithm is not available from the
     *                                  specified Provider object.
     */
    public static AlgorithmParameters getInstance(String name, Provider provider)
            throws NoSuchAlgorithmException {

        if (provider == null) {
            return AlgorithmParameters.getInstance(name);
        } else {
            return AlgorithmParameters.getInstance(name, provider);
        }
    }
}
