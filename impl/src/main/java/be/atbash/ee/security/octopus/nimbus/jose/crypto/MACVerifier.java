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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.HMAC;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.MACProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ConstantTimeUtils;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Message Authentication Code (MAC) verifier of
 * {@link JWSObject JWS objects}. Expects a secret key.
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.2">section 3.2</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#HS256}
 *     <li>{@link JWSAlgorithm#HS384}
 *     <li>{@link JWSAlgorithm#HS512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-06-26
 */
public class MACVerifier extends MACProvider implements JWSVerifier {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secret The secret. Must be at least 256 bits long and not
     *               {@code null}.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(byte[] secret)
            throws JOSEException {

        this(secret, null);
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secretString The secret as a UTF-8 encoded string. Must be at
     *                     least 256 bits long and not {@code null}.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(String secretString)
            throws JOSEException {

        this(secretString.getBytes(UTF_8));
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secretKey The secret key. Must be at least 256 bits long and
     *                  not {@code null}.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(SecretKey secretKey)
            throws JOSEException {

        this(secretKey.getEncoded());
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param jwk The secret as a JWK. Must be at least 256 bits long and
     *            not {@code null}.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(OctetSequenceKey jwk)
            throws JOSEException {

        this(jwk.toByteArray());
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param jwk            The secret as a JWK. Must be at least 256 bits long and
     *                       not {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(OctetSequenceKey jwk,
                       Set<String> defCritHeaders)
            throws JOSEException {

        this(jwk.toByteArray(), defCritHeaders);
    }

    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secret         The secret. Must be at least 256 bits long
     *                       and not {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @throws JOSEException If the secret length is shorter than the
     *                       minimum 256-bit requirement.
     */
    public MACVerifier(byte[] secret,
                       Set<String> defCritHeaders)
            throws JOSEException {

        super(secret, SUPPORTED_ALGORITHMS);

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
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

        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] expectedHMAC = HMAC.compute(jcaAlg, getSecret(), signedContent, getJCAContext().getProvider());
        return ConstantTimeUtils.areEqual(expectedHMAC, signature.decode());
    }
}
