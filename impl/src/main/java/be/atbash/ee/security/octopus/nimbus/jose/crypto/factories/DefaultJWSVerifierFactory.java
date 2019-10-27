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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.nimbus.jose.*;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JCAContext;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Default JSON Web Signature (JWS) verifier factory.
 *
 * <p>Supports all standard JWS algorithms implemented in the
 * {@link be.atbash.ee.security.octopus.nimbus.jose.crypto} package.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-11-16
 */
public class DefaultJWSVerifierFactory implements JWSVerifierFactory {


    /**
     * The supported JWS algorithms.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.addAll(MACVerifier.SUPPORTED_ALGORITHMS);
        algs.addAll(RSASSAVerifier.SUPPORTED_ALGORITHMS);
        algs.addAll(ECDSAVerifier.SUPPORTED_ALGORITHMS);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * The JCA context.
     */
    private final JCAContext jcaContext = new JCAContext();


    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {

        return SUPPORTED_ALGORITHMS;
    }


    @Override
    public JCAContext getJCAContext() {

        return jcaContext;
    }


    @Override
    public JWSVerifier createJWSVerifier(JWSHeader header, Key key)
            throws JOSEException {

        JWSVerifier verifier;

        if (MACVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof SecretKey)) {
                throw new KeyTypeException(SecretKey.class);
            }

            SecretKey macKey = (SecretKey) key;

            verifier = new MACVerifier(macKey);

        } else if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof RSAPublicKey)) {
                throw new KeyTypeException(RSAPublicKey.class);
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) key;

            verifier = new RSASSAVerifier(rsaPublicKey);

        } else if (ECDSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof ECPublicKey)) {
                throw new KeyTypeException(ECPublicKey.class);
            }

            ECPublicKey ecPublicKey = (ECPublicKey) key;

            verifier = new ECDSAVerifier(ecPublicKey);

        } else {

            throw new JOSEException("Unsupported JWS algorithm: " + header.getAlgorithm());
        }

        // Apply JCA context
        verifier.getJCAContext().setSecureRandom(jcaContext.getSecureRandom());
        verifier.getJCAContext().setProvider(jcaContext.getProvider());

        return verifier;
    }
}
