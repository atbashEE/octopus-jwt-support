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
import be.atbash.ee.security.octopus.nimbus.jose.PlainHeader;
import be.atbash.ee.security.octopus.nimbus.jose.PlainObject;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.util.JsonbUtil;

import javax.json.Json;
import javax.json.JsonObject;
import java.text.ParseException;


/**
 * Unsecured (plain) JSON Web Token (JWT).
 * <p>
 * Based on code by  Vladimir Dzhuvinov
 */
public class PlainJWT extends PlainObject implements JWT {


    private static final long serialVersionUID = 1L;


    // Cached JWTClaimsSet
    private JWTClaimsSet claimsSet;

    /**
     * Creates a new unsecured (plain) JSON Web Token (JWT) with a default
     * {@link be.atbash.ee.security.octopus.nimbus.jose.PlainHeader} and the specified claims
     * set.
     *
     * @param claimsSet The JWT claims set. Must not be {@code null}.
     */
    public PlainJWT(JWTClaimsSet claimsSet) {

        super(new Payload(claimsSet.toJSONObject()));
        this.claimsSet = claimsSet;
    }


    /**
     * Creates a new unsecured (plain) JSON Web Token (JWT) with the
     * specified header and claims set.
     *
     * @param header    The unsecured header. Must not be {@code null}.
     * @param claimsSet The JWT claims set. Must not be {@code null}.
     */
    public PlainJWT(PlainHeader header, JWTClaimsSet claimsSet) {

        super(header, new Payload(claimsSet.toJSONObject()));
        this.claimsSet = claimsSet;
    }


    /**
     * Creates a new unsecured (plain) JSON Web Token (JWT) with the
     * specified Base64URL-encoded parts.
     *
     * @param firstPart  The first part, corresponding to the unsecured
     *                   header. Must not be {@code null}.
     * @param secondPart The second part, corresponding to the claims set
     *                   (payload). Must not be {@code null}.
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public PlainJWT(Base64URLValue firstPart, Base64URLValue secondPart)
            throws ParseException {

        super(firstPart, secondPart);
    }

    public PlainJWT(PlainHeader header, JsonObject jsonObject) {
        super(header, new Payload(jsonObject));
    }

    @Override
    public JWTClaimsSet getJWTClaimsSet()
            throws ParseException {

        if (claimsSet != null) {
            return claimsSet;
        }

        JsonObject json = getPayload().toJSONObject();

        if (json == null) {

            throw new ParseException("Payload of unsecured JOSE object is not a valid JSON object", 0);
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
     * Parses an unsecured (plain) JSON Web Token (JWT) from the specified
     * string in compact format.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The unsecured JWT.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        unsecured JWT.
     */
    public static PlainJWT parse(String value)
            throws ParseException {

        Base64URLValue[] parts = JOSEObject.split(value);

        if (!parts[2].toString().isEmpty()) {

            throw new ParseException("Unexpected third Base64URL part in the unsecured JWT object", 0);
        }

        return new PlainJWT(parts[0], parts[1]);
    }

    /**
     * Parses an unsecured (plain) JSON Web Token (JWT) from
     * JSON Object.
     *
     * @param value The Json to parse. Must not be {@code null}.
     * @return The unsecured JWT.
     * @throws ParseException If the JsonObject couldn't be parsed to a valid
     *                        unsecured JWT.
     */
    public static PlainJWT parse(JsonObject value)
            throws ParseException {

        Base64URLValue header = JSONObjectUtils.getBase64URL(value, "protected");
        if (header == null) {
            header = Base64URLValue.encode(JsonbUtil.getJsonb().toJson(value.getJsonObject("header")));
        }

        Base64URLValue payload = JSONObjectUtils.getBase64URL(value, "payload");

        return new PlainJWT(header, payload);
    }

    @Override
    public JsonObject serializeToJson() {
        return Json.createObjectBuilder()
                .add("header", getHeader().toJSONObject().build())
                .add("protected", getHeader().toBase64URL().toString())
                .add("payload", getPayload().toBase64URL().toString())
                .build();
    }
}
