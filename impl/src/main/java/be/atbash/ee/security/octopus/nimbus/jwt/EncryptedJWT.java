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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEObject;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import jakarta.json.JsonObject;
import java.text.ParseException;


/**
 * Encrypted JSON Web Token (JWT). This class is thread-safe.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class EncryptedJWT extends JWEObject implements JWT {


    private static final long serialVersionUID = 1L;


    /**
     * Creates a new to-be-encrypted JSON Web Token (JWT) with the specified
     * header and claims set. The initial state will be
     * {@link JWEObject.State#UNENCRYPTED unencrypted}.
     *
     * @param header    The JWE header. Must not be {@code null}.
     * @param claimsSet The JWT claims set. Must not be {@code null}.
     */
    public EncryptedJWT(JWEHeader header, JWTClaimsSet claimsSet) {

        super(header, new Payload(claimsSet.toJSONObject()));
    }


    /**
     * Creates a new encrypted JSON Web Token (JWT) with the specified
     * serialised parts. The state will be
     * {@link JWEObject.State#ENCRYPTED encrypted}.
     *
     * @param firstPart  The first part, corresponding to the JWE header.
     *                   Must not be {@code null}.
     * @param secondPart The second part, corresponding to the encrypted
     *                   key. Empty or {@code null} if none.
     * @param thirdPart  The third part, corresponding to the initialisation
     *                   vectory. Empty or {@code null} if none.
     * @param fourthPart The fourth part, corresponding to the cipher text.
     *                   Must not be {@code null}.
     * @param fifthPart  The fifth part, corresponding to the integrity
     *                   value. Empty of {@code null} if none.
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public EncryptedJWT(Base64URLValue firstPart,
                        Base64URLValue secondPart,
                        Base64URLValue thirdPart,
                        Base64URLValue fourthPart,
                        Base64URLValue fifthPart)
            throws ParseException {

        super(firstPart, secondPart, thirdPart, fourthPart, fifthPart);
    }


    @Override
    public JWTClaimsSet getJWTClaimsSet()
            throws ParseException {

        Payload payload = getPayload();

        if (payload == null) {
            return null;
        }

        JsonObject json = payload.toJSONObject();

        if (json == null) {
            throw new ParseException("Payload of JWE object is not a valid JSON object", 0);
        }

        return JWTClaimsSet.parse(json);
    }


    /**
     * Parses an encrypted JSON Web Token (JWT) from the specified string in
     * compact format.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The encrypted JWT.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        encrypted JWT.
     */
    public static EncryptedJWT parse(String value)
            throws ParseException {

        Base64URLValue[] parts = JOSEObject.split(value);

        if (parts.length != 5) {
            throw new ParseException("Unexpected number of Base64URL parts, must be five", 0);
        }

        return new EncryptedJWT(parts[0], parts[1], parts[2], parts[3], parts[4]);
    }
}
