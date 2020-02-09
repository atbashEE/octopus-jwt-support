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


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSProvider;

import java.util.Collections;
import java.util.Set;


/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public abstract class BaseJWSProvider implements JWSProvider {


    /**
     * The supported algorithms by the JWS provider instance.
     */
    private final Set<JWSAlgorithm> algs;


    /**
     * Creates a new base JWS provider.
     *
     * @param algs The supported algorithms by the JWS provider instance.
     *             Must not be {@code null}.
     */
    BaseJWSProvider(Set<JWSAlgorithm> algs) {

        if (algs == null) {
            throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
        }

        this.algs = Collections.unmodifiableSet(algs);
    }


    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {

        return algs;
    }

}

