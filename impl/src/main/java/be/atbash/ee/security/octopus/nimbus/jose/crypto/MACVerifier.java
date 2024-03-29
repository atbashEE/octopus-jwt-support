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
import org.slf4j.MDC;

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
 * Based on code by Vladimir Dzhuvinov
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
     */
    public MACVerifier(byte[] secret) {

        this(secret, null);
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secretString The secret as a UTF-8 encoded string. Must be at
     *                     least 256 bits long and not {@code null}.
     */
    public MACVerifier(String secretString) {

        this(secretString.getBytes(UTF_8));
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secretKey The secret key. Must be at least 256 bits long and
     *                  not {@code null}.
     */
    public MACVerifier(SecretKey secretKey) {

        this(secretKey.getEncoded());
    }

    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param secretKey      The secret key. Must be at least 256 bits long and
     *                       not {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public MACVerifier(SecretKey secretKey,
                       Set<String> defCritHeaders) {

        this(secretKey.getEncoded(), defCritHeaders);
    }


    /**
     * Creates a new Message Authentication (MAC) verifier.
     *
     * @param jwk The secret as a JWK. Must be at least 256 bits long and
     *            not {@code null}.
     */
    public MACVerifier(OctetSequenceKey jwk) {

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
     */
    public MACVerifier(OctetSequenceKey jwk,
                       Set<String> defCritHeaders) {

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
     */
    public MACVerifier(byte[] secret,
                       Set<String> defCritHeaders) {

        super(secret, SUPPORTED_ALGORITHMS);

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    @Override
    public boolean verify(JWSHeader header,
                          byte[] signedContent,
                          Base64URLValue signature) {

        if (!critPolicy.headerPasses(header)) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "Verification failed due to 'crit' header parameter deferral policy");
            return false;
        }

        String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
        byte[] expectedHMAC = HMAC.compute(jcaAlg, getSecret(), signedContent);
        return ConstantTimeUtils.areEqual(expectedHMAC, signature.decode());
    }
}
