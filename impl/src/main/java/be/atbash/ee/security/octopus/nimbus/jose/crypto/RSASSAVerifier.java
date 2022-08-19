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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.slf4j.MDC;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;


/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) verifier of
 * {@link JWSObject JWS objects}. Expects a public RSA key.
 *
 * <p>See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3">3.3</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.5">3.5</a> for more
 * information.
 *
 * <p>This class is thread-safe.
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
public class RSASSAVerifier extends RSASSAProvider implements JWSVerifier {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * The public RSA key.
     */
    private final RSAPublicKey publicKey;


    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
     *
     * @param publicKey The public RSA key. Must not be {@code null}.
     */
    public RSASSAVerifier(RSAPublicKey publicKey) {

        this(publicKey, null);
    }

    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
     *
     * @param atbashKey The public RSA key. Must not be {@code null}.
     */
    public RSASSAVerifier(AtbashKey atbashKey) {

        this(getPublicKey(atbashKey));
    }

    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
     *
     * @param atbashKey      The public RSA key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public RSASSAVerifier(AtbashKey atbashKey,
                          Set<String> defCritHeaders) {

        this(getPublicKey(atbashKey), defCritHeaders);
    }

    private static RSAPublicKey getPublicKey(AtbashKey atbashKey) {
        if (atbashKey.getSecretKeyType().getKeyType() != KeyType.RSA) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PUBLIC) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        return (RSAPublicKey) atbashKey.getKey();
    }

    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
     *
     * @param publicKey      The public RSA key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public RSASSAVerifier(RSAPublicKey publicKey,
                          Set<String> defCritHeaders) {

        if (publicKey == null) {
            throw new IllegalArgumentException("The public RSA key must not be null");
        }

        this.publicKey = publicKey;

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getDeferredCriticalHeaderParams();
    }


    @Override
    public boolean verify(JWSHeader header,
                          byte[] signedContent,
                          Base64URLValue signature) {

        JWSAlgorithm alg = header.getAlgorithm();

        if (!supportedJWSAlgorithms().contains(alg)) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format("Signature algorithm specified in Header %s is not supported.", alg.getName()));
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }

        if (!critPolicy.headerPasses(header)) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "Verification failed due to 'crit' header parameter deferral policy");
            return false;
        }

        Signature verifier = RSASSA.getSignerAndVerifier(header.getAlgorithm());

        try {
            verifier.initVerify(publicKey);

        } catch (InvalidKeyException e) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "Selected Public RSA key is not valid");
            throw new JOSEException("Invalid public RSA key: " + e.getMessage(), e);
        }

        try {
            verifier.update(signedContent);
            return verifier.verify(signature.decode());

        } catch (SignatureException e) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "Signature verification failed with provided Public RSA key");
            return false;
        }
    }
}
