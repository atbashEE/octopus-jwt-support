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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Key (JWK) set. Represented by a JSON object that contains an array
 * of {@link JWK JSON Web Keys} (JWKs) as the value of its "keys" member.
 * Additional (custom) members of the JWK Set JSON object are also supported.
 *
 * <p>Example JSON Web Key (JWK) set:
 *
 * <pre>
 * {
 *   "keys" : [ { "kty" : "EC",
 *                "crv" : "P-256",
 *                "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *                "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *                "use" : "enc",
 *                "kid" : "1" },
 *
 *              { "kty" : "RSA",
 *                "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *                         4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *                         tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *                         QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *                         SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *                         w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *                "e"   : "AQAB",
 *                "alg" : "RS256",
 *                "kid" : "2011-04-29" } ]
 * }
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov and Vedran Pavic
 */
public class JWKSet {

    /**
     * The MIME type of JWK set objects:
     * {@code application/jwk-set+json; charset=UTF-8}
     */
    public static final String MIME_TYPE = "application/jwk-set+json; charset=UTF-8";


    /**
     * The JWK list.
     */
    private final List<JWK> keys;


    /**
     * Additional custom members.
     */
    private final Map<String, Object> customMembers;


    /**
     * Creates a new empty JSON Web Key (JWK) set.
     */
    public JWKSet() {

        this(Collections.emptyList());
    }


    /**
     * Creates a new JSON Web Key (JWK) set with a single key.
     *
     * @param key The JWK. Must not be {@code null}.
     */
    public JWKSet(JWK key) {

        this(Collections.singletonList(key));

        if (key == null) {
            throw new IllegalArgumentException("The JWK must not be null");
        }
    }


    /**
     * Creates a new JSON Web Key (JWK) set with the specified keys.
     *
     * @param keys The JWK list. Must not be {@code null}.
     */
    public JWKSet(List<JWK> keys) {

        this(keys, Collections.emptyMap());
    }


    /**
     * Creates a new JSON Web Key (JWK) set with the specified keys and
     * additional custom members.
     *
     * @param keys          The JWK list. Must not be {@code null}.
     * @param customMembers The additional custom members. Must not be
     *                      {@code null}.
     */
    public JWKSet(List<JWK> keys, Map<String, Object> customMembers) {

        if (keys == null) {
            throw new IllegalArgumentException("The JWK list must not be null");
        }

        this.keys = Collections.unmodifiableList(keys);

        this.customMembers = Collections.unmodifiableMap(customMembers);
    }


    /**
     * Gets the keys (ordered) of this JSON Web Key (JWK) set.
     *
     * @return The keys, empty list if none.
     */
    public List<JWK> getKeys() {

        return keys;
    }

    /**
     * Gets the AtbashKey of this JSON Web Key (JWK) set.
     *
     * @return The keys, empty list if none.
     */
    public List<AtbashKey> getAtbashKeys() {

        List<AtbashKey> result = new ArrayList<>();
        for (JWK jwk : keys) {
            if (jwk instanceof AsymmetricJWK) {
                AsymmetricJWK asymmetricJWK = (AsymmetricJWK) jwk;
                PrivateKey privateKey = asymmetricJWK.toPrivateKey();
                if (privateKey != null) {
                    result.add(new AtbashKey(jwk.getKeyID(), privateKey));
                }
                PublicKey publicKey = asymmetricJWK.toPublicKey();
                if (publicKey != null) {
                    result.add(new AtbashKey(jwk.getKeyID(), publicKey));
                }
            } else {
                OctetSequenceKey octetSequenceKey = (OctetSequenceKey) jwk;
                result.add(new AtbashKey(jwk.getKeyID(), octetSequenceKey.toSecretKey()));
            }
        }
        return result;
    }

    /**
     * Gets the key from this JSON Web Key (JWK) set as identified by its
     * Key ID (kid) member.
     *
     * <p>If more than one key exists in the JWK Set with the same
     * identifier, this function returns only the first one in the set.
     *
     * @param kid They key identifier.
     * @return The key identified by {@code kid} or {@code null} if no key
     * exists.
     */
    public JWK getKeyByKeyId(String kid) {

        for (JWK key : getKeys()) {

            if (key.getKeyID() != null && key.getKeyID().equals(kid)) {
                return key;
            }
        }

        // no key found
        return null;
    }


    /**
     * Gets the additional custom members of this JSON Web Key (JWK) set.
     *
     * @return The additional custom members, empty map if none.
     */
    public Map<String, Object> getAdditionalMembers() {

        return customMembers;
    }


    /**
     * Returns a copy of this JSON Web Key (JWK) set with all private keys
     * and parameters removed.
     *
     * @return A copy of this JWK set with all private keys and parameters
     * removed.
     */
    public JWKSet toPublicJWKSet() {

        List<JWK> publicKeyList = new LinkedList<>();

        for (JWK key : keys) {

            JWK publicKey = key.toPublicJWK();

            if (publicKey != null) {
                publicKeyList.add(publicKey);
            }
        }

        return new JWKSet(publicKeyList, customMembers);
    }


    /**
     * Returns the JSON object representation of this JSON Web Key (JWK)
     * set. Private keys and parameters will be omitted from the output.
     * Use the alternative {@link #toJSONObject(boolean)} method if you
     * wish to include them.
     *
     * @return The JSON object representation.
     */
    public JsonObject toJSONObject() {

        return toJSONObject(true);
    }


    /**
     * Returns the JSON object representation of this JSON Web Key (JWK)
     * set.
     *
     * @param publicKeysOnly Controls the inclusion of private keys and
     *                       parameters into the output JWK members. If
     *                       {@code true} private keys and parameters will
     *                       be omitted. If {@code false} all available key
     *                       parameters will be included.
     * @return The JSON object representation.
     */
    public JsonObject toJSONObject(boolean publicKeysOnly) {

        JsonObjectBuilder result = Json.createObjectBuilder(customMembers);

        JsonArrayBuilder keysArray = Json.createArrayBuilder();


        for (JWK key : keys) {

            if (publicKeysOnly) {

                // Try to get public key, then serialise
                JWK publicKey = key.toPublicJWK();

                if (publicKey != null) {
                    keysArray.add(publicKey.toJSONObject());
                }
            } else {

                keysArray.add(key.toJSONObject());
            }
        }

        result.add(JWKIdentifiers.KEYS, keysArray);

        return result.build();
    }


    /**
     * Returns the JSON object string representation of this JSON Web Key
     * (JWK) set.
     *
     * @return The JSON object string representation.
     */
    @Override
    public String toString() {

        return toJSONObject().toString();
    }


    /**
     * Parses the specified string representing a JSON Web Key (JWK) set.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The JWK set.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        JSON Web Key (JWK) set.
     */
    public static JWKSet parse(String value)
            throws ParseException {

        return parse(JSONObjectUtils.parse(value));
    }


    /**
     * Parses the specified JSON object representing a JSON Web Key (JWK)
     * set.
     *
     * @param json The JSON object to parse. Must not be {@code null}.
     * @return The JWK set.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        JSON Web Key (JWK) set.
     */
    public static JWKSet parse(JsonObject json)
            throws ParseException {

        JsonArray keyArray = json.getJsonArray(JWKIdentifiers.KEYS);

        if (keyArray == null) {
            throw new ParseException("Missing required \"" + JWKIdentifiers.KEYS + "\" member", 0);
        }

        List<JWK> keys = new LinkedList<>();

        for (int i = 0; i < keyArray.size(); i++) {

            if (!(keyArray.get(i) instanceof JsonObject)) {
                throw new ParseException("The \"keys\" JSON array must contain JSON objects only", 0);
            }

            JsonObject keyJSON = (JsonObject) keyArray.get(i);

            try {
                JWK parse = JWK.parse(keyJSON);
                if (parse != null) {
                    keys.add(parse);
                }

            } catch (ParseException e) {

                throw new ParseException("Invalid JWK at position " + i + ": " + e.getMessage(), 0);
            }
        }

        // Parse additional custom members
        Map<String, Object> additionalMembers = new HashMap<>();
        for (Map.Entry<String, JsonValue> entry : json.entrySet()) {

            if (entry.getKey() == null || entry.getKey().equals(JWKIdentifiers.KEYS)) {
                continue;
            }

            additionalMembers.put(entry.getKey(), JSONObjectUtils.getJsonValueAsObject(entry.getValue()));
        }

        return new JWKSet(keys, additionalMembers);
    }

}
