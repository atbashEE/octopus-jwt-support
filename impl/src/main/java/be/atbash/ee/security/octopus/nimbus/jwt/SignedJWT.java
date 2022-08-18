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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEObject;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.util.JsonbUtil;
import jakarta.json.JsonObject;

import java.text.ParseException;


/**
 * Signed JSON Web Token (JWT).
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class SignedJWT extends JWSObject implements JWT {


    // Cached JWTClaimsSet
    private JWTClaimsSet claimsSet;

    /**
     * Creates a new to-be-signed JSON Web Token (JWT) with the specified
     * header and claims set. The initial state will be
     * {@link JWSObject.State#UNSIGNED unsigned}.
     *
     * @param header    The JWS header. Must not be {@code null}.
     * @param claimsSet The JWT claims set. Must not be {@code null}.
     */
    public SignedJWT(JWSHeader header, JWTClaimsSet claimsSet) {

        super(header, new Payload(claimsSet.toJSONObject()));
        this.claimsSet = claimsSet;
    }


    /**
     * Creates a new signed JSON Web Token (JWT) with the specified
     * serialised parts. The state will be
     * {@link JWSObject.State#SIGNED signed}.
     *
     * @param firstPart  The first part, corresponding to the JWS header.
     *                   Must not be {@code null}.
     * @param secondPart The second part, corresponding to the claims set
     *                   (payload). Must not be {@code null}.
     * @param thirdPart  The third part, corresponding to the signature.
     *                   Must not be {@code null}.
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public SignedJWT(Base64URLValue firstPart, Base64URLValue secondPart, Base64URLValue thirdPart)
            throws ParseException {

        super(firstPart, secondPart, thirdPart);
    }


    @Override
    public JWTClaimsSet getJWTClaimsSet()
            throws ParseException {

        if (claimsSet != null) {
            return claimsSet;
        }

        JsonObject json = getPayload().toJSONObject();

        if (json == null) {
            throw new ParseException("Payload of JWS object is not a valid JSON object", 0);
        }

        claimsSet = JWTClaimsSet.parse(json);
        return claimsSet;
    }

    @Override
    protected void setPayload(Payload payload) {

        // setPayload() changes the result of getJWTClaimsSet().
        // set claimsSet = null and reparse payload again when called getJWTClaimsSet().
        claimsSet = null;
        super.setPayload(payload);
    }

    /**
     * Parses a signed JSON Web Token (JWT) from the specified string in
     * compact format.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The signed JWT.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        signed JWT.
     */
    public static SignedJWT parse(String value)
            throws ParseException {

        Base64URLValue[] parts = JOSEObject.split(value);

        if (parts.length != 3) {
            throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
        }

        return new SignedJWT(parts[0], parts[1], parts[2]);
    }

    /**
     * Parses a signed JSON Web Token (JWT) from the specified string in
     * compact format.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The signed JWT.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        signed JWT.
     */
    public static SignedJWT parse(JsonObject value)
            throws ParseException {
        Base64URLValue header = JSONObjectUtils.getBase64URL(value, "protected");
        if (header == null) {
            header = Base64URLValue.encode(JsonbUtil.getJsonb().toJson(value.getJsonObject("header")));
        }

        Base64URLValue payload = JSONObjectUtils.getBase64URL(value, "payload");
        Base64URLValue signature = JSONObjectUtils.getBase64URL(value, "signature");


        return new SignedJWT(header, payload, signature);
    }
}
