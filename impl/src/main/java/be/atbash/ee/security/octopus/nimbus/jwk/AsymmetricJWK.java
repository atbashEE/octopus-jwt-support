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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.exception.InvalidKeyException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/**
 * Asymmetric (pair) JSON Web Key (JWK).
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-02-27
 */
public interface AsymmetricJWK {


    /**
     * Returns a Java public key representation of the JWK.
     *
     * @return The Java public key.
     * @throws InvalidKeyException If conversion failed or is not supported.
     */
    PublicKey toPublicKey();


    /**
     * Returns a Java private key representation of this JWK.
     *
     * @return The Java private key, {@code null} if not specified.
     * @throws InvalidKeyException If conversion failed or is not supported.
     */
    PrivateKey toPrivateKey();


    /**
     * Returns a Java key pair representation of this JWK.
     *
     * @return The Java key pair. The private key will be {@code null} if
     * not specified.
     * @throws InvalidKeyException If conversion failed or is not supported.
     */
    KeyPair toKeyPair();


    /**
     * Returns {@code true} if the public key material of this JWK matches
     * the public subject key info of the specified X.509 certificate.
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return {@code true} if the public key material of this JWK matches
     * the public subject key info of the specified X.509
     * certificate, else {@code false}.
     */
    boolean matches(X509Certificate cert);
}
