/*
 * Copyright 2017-2022 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for RSA signers and verifiers of {@link
 * JWSObject JWS objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#RS256}
 *     <li>{@link JWSAlgorithm#RS384}
 *     <li>{@link JWSAlgorithm#RS512}
 *     <li>{@link JWSAlgorithm#PS256}
 *     <li>{@link JWSAlgorithm#PS384}
 *     <li>{@link JWSAlgorithm#PS512}
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public abstract class RSASSAProvider extends BaseJWSProvider {


    /**
     * The supported JWS algorithms by the RSA-SSA provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


    static {
        // This list must match RSASSA.getSignerAndVerifier
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.RS256);
        algs.add(JWSAlgorithm.RS384);
        algs.add(JWSAlgorithm.RS512);
        algs.add(JWSAlgorithm.PS256);
        algs.add(JWSAlgorithm.PS384);
        algs.add(JWSAlgorithm.PS512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * Creates a new RSASSA provider.
     */
    protected RSASSAProvider() {

        super(SUPPORTED_ALGORITHMS);
    }
}

