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


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEProvider;

import java.util.Collections;
import java.util.Set;


/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and
 * decrypters.
 *
 * Based on code by Vladimir Dzhuvinov
 */
abstract class BaseJWEProvider implements JWEProvider {


    /**
     * The supported algorithms by the JWE provider instance.
     */
    private final Set<JWEAlgorithm> algs;


    /**
     * The supported encryption methods by the JWE provider instance.
     */
    private final Set<EncryptionMethod> encs;


    /**
     * Creates a new base JWE provider.
     *
     * @param algs The supported algorithms by the JWE provider instance.
     *             Must not be {@code null}.
     * @param encs The supported encryption methods by the JWE provider
     *             instance. Must not be {@code null}.
     */
    BaseJWEProvider(Set<JWEAlgorithm> algs,
                    Set<EncryptionMethod> encs) {

        if (algs == null) {
            throw new IllegalArgumentException("The supported JWE algorithm set must not be null");
        }

        this.algs = Collections.unmodifiableSet(algs);


        if (encs == null) {
            throw new IllegalArgumentException("The supported encryption methods must not be null");
        }

        this.encs = encs;
    }


    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {

        return algs;
    }


    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {

        return encs;
    }
}

