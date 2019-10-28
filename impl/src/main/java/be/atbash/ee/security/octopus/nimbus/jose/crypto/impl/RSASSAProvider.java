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


import be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for RSA signers and verifiers of {@link
 * be.atbash.ee.security.octopus.nimbus.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#RS256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#RS384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#RS512}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#PS256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#PS384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm#PS512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-31
 */
public abstract class RSASSAProvider extends BaseJWSProvider {


    /**
     * The supported JWS algorithms by the RSA-SSA provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


    static {
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
