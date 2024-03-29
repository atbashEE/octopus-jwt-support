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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.Ed25519Verifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.MACProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSAProvider;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.slf4j.MDC;

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
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class DefaultJWSVerifierFactory implements JWSVerifierFactory {


    /**
     * The supported JWS algorithms.
     */
    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;
    private static final String TYPES_DO_NOT_MATCH = "The header algorithm '%s' and the Key type '%s' do no match";


    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.addAll(MACProvider.SUPPORTED_ALGORITHMS);
        algs.addAll(RSASSAProvider.SUPPORTED_ALGORITHMS);
        algs.addAll(ECDSAProvider.SUPPORTED_ALGORITHMS);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {

        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public JWSVerifier createJWSVerifier(JWSHeader header, Key key, Set<String> defCritHeaders) {

        JWSVerifier verifier;

        if (MACVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof SecretKey)) {
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format(TYPES_DO_NOT_MATCH, header.getAlgorithm(), key.getClass().getName()));
                throw new KeyTypeException(SecretKey.class);
            }

            SecretKey macKey = (SecretKey) key;

            verifier = new MACVerifier(macKey, defCritHeaders);

        } else if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof RSAPublicKey)) {
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format(TYPES_DO_NOT_MATCH, header.getAlgorithm(), key.getClass().getName()));
                throw new KeyTypeException(RSAPublicKey.class);
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) key;

            verifier = new RSASSAVerifier(rsaPublicKey, defCritHeaders);

        } else if (ECDSAVerifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof ECPublicKey)) {
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format(TYPES_DO_NOT_MATCH, header.getAlgorithm(), key.getClass().getName()));
                throw new KeyTypeException(ECPublicKey.class);
            }

            ECPublicKey ecPublicKey = (ECPublicKey) key;

            verifier = new ECDSAVerifier(ecPublicKey, defCritHeaders);

        } else if (Ed25519Verifier.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {

            if (!(key instanceof BCEdDSAPublicKey)) {
                // TODO better to check for EdDSAKey and PublicKey?
                MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format(TYPES_DO_NOT_MATCH, header.getAlgorithm(), key.getClass().getName()));
                throw new KeyTypeException(BCEdDSAPublicKey.class);
            }

            BCEdDSAPublicKey okpPublicKey = (BCEdDSAPublicKey) key;
            verifier = new Ed25519Verifier(okpPublicKey, defCritHeaders);
        } else {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format("No Signature verifier found for the algorithm specified in Header %s.", header.getAlgorithm().getName()));
            throw new JOSEException("Unsupported JWS algorithm: " + header.getAlgorithm());
        }

        return verifier;
    }
}
