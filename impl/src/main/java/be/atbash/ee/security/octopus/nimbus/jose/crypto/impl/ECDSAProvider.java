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


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for Elliptic Curve Digital Signature Algorithm
 * (ECDSA) signers and validators of {@link JWSObject JWS
 * objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#ES256}
 *     <li>{@link JWSAlgorithm#ES256K}
 *     <li>{@link JWSAlgorithm#ES384}
 *     <li>{@link JWSAlgorithm#ES512}
 * </ul>
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 2017-05-13
 */
public abstract class ECDSAProvider extends BaseJWSProvider {


    /**
     * The supported JWS algorithms by the EC-DSA provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.ES256);
        algs.add(JWSAlgorithm.ES256K);
        algs.add(JWSAlgorithm.ES384);
        algs.add(JWSAlgorithm.ES512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * provider.
     *
     * @param alg The EC-DSA algorithm. Must be supported and not
     *            {@code null}.
     * @throws JOSEException If JWS algorithm is not supported.
     */
    protected ECDSAProvider(JWSAlgorithm alg)
            throws JOSEException {

        super(new HashSet<>(Collections.singletonList(alg)));

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException("Unsupported EC DSA algorithm: " + alg);
        }
    }


    /**
     * Returns the supported ECDSA algorithm.
     *
     * @return The supported ECDSA algorithm.
     * @see #supportedJWSAlgorithms()
     */
    public JWSAlgorithm supportedECDSAAlgorithm() {

        return supportedJWSAlgorithms().iterator().next();
    }
}

