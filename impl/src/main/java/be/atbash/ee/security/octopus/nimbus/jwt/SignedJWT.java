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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEObject;
import be.atbash.ee.security.octopus.nimbus.jose.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jose.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.json.JsonObject;
import java.text.ParseException;


/**
 * Signed JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-19
 */
public class SignedJWT extends JWSObject implements JWT {


    private static final long serialVersionUID = 1L;


    /**
     * Creates a new to-be-signed JSON Web Token (JWT) with the specified
     * header and claims set. The initial state will be
     * {@link be.atbash.ee.security.octopus.nimbus.jose.JWSObject.State#UNSIGNED unsigned}.
     *
     * @param header    The JWS header. Must not be {@code null}.
     * @param claimsSet The JWT claims set. Must not be {@code null}.
     */
    public SignedJWT(final JWSHeader header, final JWTClaimsSet claimsSet) {

        super(header, new Payload(claimsSet.toJSONObject()));
    }


    /**
     * Creates a new signed JSON Web Token (JWT) with the specified
     * serialised parts. The state will be
     * {@link be.atbash.ee.security.octopus.nimbus.jose.JWSObject.State#SIGNED signed}.
     *
     * @param firstPart  The first part, corresponding to the JWS header.
     *                   Must not be {@code null}.
     * @param secondPart The second part, corresponding to the claims set
     *                   (payload). Must not be {@code null}.
     * @param thirdPart  The third part, corresponding to the signature.
     *                   Must not be {@code null}.
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public SignedJWT(final Base64URLValue firstPart, final Base64URLValue secondPart, final Base64URLValue thirdPart)
            throws ParseException {

        super(firstPart, secondPart, thirdPart);
    }


    @Override
    public JWTClaimsSet getJWTClaimsSet()
            throws ParseException {

        JsonObject json = getPayload().toJSONObject();

        if (json == null) {
            throw new ParseException("Payload of JWS object is not a valid JSON object", 0);
        }

        return JWTClaimsSet.parse(json);
    }


    /**
     * Parses a signed JSON Web Token (JWT) from the specified string in
     * compact format.
     *
     * @param s The string to parse. Must not be {@code null}.
     * @return The signed JWT.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        signed JWT.
     */
    public static SignedJWT parse(final String s)
            throws ParseException {

        Base64URLValue[] parts = JOSEObject.split(s);

        if (parts.length != 3) {
            throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
        }

        return new SignedJWT(parts[0], parts[1], parts[2]);
    }
}