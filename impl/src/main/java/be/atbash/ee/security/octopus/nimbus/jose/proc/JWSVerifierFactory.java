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
package be.atbash.ee.security.octopus.nimbus.jose.proc;


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSProvider;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;

import java.security.Key;
import java.util.Set;


/**
 * JSON Web Signature (JWS) verifier factory.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public interface JWSVerifierFactory extends JWSProvider {


    /**
     * Creates a new JWS verifier for the specified header and key.
     *
     * @param header The JWS header. Not {@code null}.
     * @param key    The key intended to verify the JWS message. Not
     *               {@code null}.
     * @return The JWS verifier.
     */
    default JWSVerifier createJWSVerifier(JWSHeader header, Key key) {
        return createJWSVerifier(header, key, null);
    }

    /**
     * Creates a new JWS verifier for the specified header and key with indication of deferred critical parameters.
     *
     * @param header        The JWS header. Not {@code null}.
     * @param key           The key intended to verify the JWS message. Not
     *                      {@code null}.
     * @param defCritHeader The Set of critical Header names that are understood by the application
     * @return The JWS verifier.
     */
    JWSVerifier createJWSVerifier(JWSHeader header, Key key, Set<String> defCritHeader);
}
