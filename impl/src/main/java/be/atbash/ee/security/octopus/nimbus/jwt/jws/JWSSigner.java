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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

/**
 * JSON Web Signature (JWS) signer.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public interface JWSSigner extends JWSProvider {


    /**
     * Signs the specified {@link JWSObject#getSigningInput input} of a
     * {@link JWSObject JWS object}.
     *
     * @param header       The JSON Web Signature (JWS) header. Must
     *                     specify a supported JWS algorithm and must not
     *                     be {@code null}.
     * @param signingInput The input to sign. Must not be {@code null}.
     * @return The resulting signature part (third part) of the JWS object.
     * @throws JOSEException If the JWS algorithm is not supported, if a
     *                       critical header parameter is not supported or
     *                       marked for deferral to the application, or if
     *                       signing failed for some other internal reason.
     */
    Base64URLValue sign(JWSHeader header, byte[] signingInput)
            throws JOSEException;
}
