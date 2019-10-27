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


import be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for RSA encrypters and decrypters of
 * {@link be.atbash.ee.security.octopus.nimbus.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#RSA_OAEP}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#RSA_OAEP_256}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A192GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version 2015-05-26
 */
public abstract class RSACryptoProvider extends BaseJWEProvider {


    /**
     * The supported JWE algorithms by the RSA crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods by the RSA crypto provider class.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.RSA1_5);
        algs.add(JWEAlgorithm.RSA_OAEP);
        algs.add(JWEAlgorithm.RSA_OAEP_256);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * Creates a new RSA encryption / decryption provider.
     */
    protected RSACryptoProvider() {

        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
    }
}
