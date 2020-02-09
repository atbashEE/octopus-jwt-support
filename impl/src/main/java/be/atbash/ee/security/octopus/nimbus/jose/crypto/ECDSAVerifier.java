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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ECChecks;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Set;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) verifier of
 * {@link JWSObject JWS objects}. Expects a public EC key
 * (with a P-256, P-384 or P-521 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.4">section 3.4</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#ES256}
 *     <li>{@link JWSAlgorithm#ES384}
 *     <li>{@link JWSAlgorithm#ES512}
 * </ul>
 *
 * Based on code by Axel Nennker and Vladimir Dzhuvinov
 */
public class ECDSAVerifier extends ECDSAProvider implements JWSVerifier {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * The public EC key.
     */
    private final ECPublicKey publicKey;


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * verifier.
     *
     * @param publicKey The public EC key. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSAVerifier(ECPublicKey publicKey)
            throws JOSEException {

        this(publicKey, null);
    }


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * verifier.
     *
     * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSAVerifier(ECKey ecJWK)
            throws JOSEException {

        this(ecJWK.toECPublicKey());
    }


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * verifier.
     *
     * @param publicKey      The public EC key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSAVerifier(ECPublicKey publicKey, Set<String> defCritHeaders)
            throws JOSEException {

        super(ECDSA.resolveAlgorithm(publicKey));

        this.publicKey = publicKey;

        if (!ECChecks.isPointOnCurve(
                publicKey,
                Curve.forJWSAlgorithm(supportedECDSAAlgorithm()).iterator().next().toECParameterSpec())) {
            throw new JOSEException("Curve / public key parameters mismatch");
        }

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }


    /**
     * Returns the public EC key.
     *
     * @return The public EC key.
     */
    public ECPublicKey getPublicKey() {

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

        JWSAlgorithm alg = header.getAlgorithm();

        if (!supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }

        if (!critPolicy.headerPasses(header)) {
            return false;
        }

        byte[] jwsSignature = signature.decode();

        byte[] derSignature;

        try {
            derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);
        } catch (JOSEException e) {
            // Invalid signature format
            return false;
        }

        Signature sig = ECDSA.getSignerAndVerifier(alg);

        try {
            sig.initVerify(publicKey);
            sig.update(signedContent);
            return sig.verify(derSignature);

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid EC public key: " + e.getMessage(), e);
        } catch (SignatureException e) {
            return false;
        }
    }
}
