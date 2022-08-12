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


import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.json.JsonObject;
import java.io.Serializable;
import java.text.ParseException;


/**
 * JSON Web Token (JWT) interface.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public interface JWT extends Serializable {


    /**
     * Gets the JOSE header of the JSON Web Token (JWT).
     *
     * @return The header.
     */
    Header getHeader();


    /**
     * Gets the claims set of the JSON Web Token (JWT).
     *
     * @return The claims set, {@code null} if not available (for an
     * encrypted JWT that isn't decrypted).
     * @throws ParseException If the payload of the JWT doesn't represent a
     *                        valid JSON object and a JWT claims set.
     */
    JWTClaimsSet getJWTClaimsSet()
            throws ParseException;


    /**
     * Gets the original parsed Base64URL parts used to create the JSON Web
     * Token (JWT).
     *
     * @return The original Base64URL parts used to creates the JWT,
     * {@code null} if the JWT was created from scratch. The
     * individual parts may be empty or {@code null} to indicate a
     * missing part.
     */
    Base64URLValue[] getParsedParts();


    /**
     * Gets the original parsed string used to create the JSON Web Token
     * (JWT).
     *
     * @return The parsed string used to create the JWT, {@code null} if
     * the JWT was created from scratch.
     * @see #getParsedParts
     */
    String getParsedString();


    /**
     * Serialises the JSON Web Token (JWT) to its compact format consisting
     * of Base64URL-encoded parts delimited by period ('.') characters.
     *
     * @return The serialised JWT.
     * @throws IllegalStateException If the JWT is not in a state that
     *                               permits serialisation.
     */
    String serialize();

    /**
     * Serialize to the Flattened JWS/JWE JSON Serialization.
     *
     * @return JsonObject with serialized content of JWS/JWE.
     */
    JsonObject serializeToJson();
}
