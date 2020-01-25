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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
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
 * @author Vladimir Dzhuvinov
 * @version 2015-06-02
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
     * @param rsaJWK The RSA JSON Web Key (JWK). Must not be {@code null}.
     *
     */
    public RSASSAVerifier(RSAKey rsaJWK) {

        this(rsaJWK.toRSAPublicKey(), null);
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


    /**
     * Gets the public RSA key.
     *
     * @return The public RSA key.
     */
    public RSAPublicKey getPublicKey() {

        return publicKey;
    }


    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public boolean verify(JWSHeader header,
                          byte[] signedContent,
                          Base64URLValue signature)
            throws JOSEException {

        if (!critPolicy.headerPasses(header)) {
            return false;
        }

        Signature verifier = RSASSA.getSignerAndVerifier(header.getAlgorithm());

        try {
            verifier.initVerify(publicKey);

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid public RSA key: " + e.getMessage(), e);
        }

        try {
            verifier.update(signedContent);
            return verifier.verify(signature.decode());

        } catch (SignatureException e) {
            return false;
        }
    }
}
