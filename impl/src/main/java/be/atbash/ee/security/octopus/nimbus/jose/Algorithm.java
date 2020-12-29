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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

import jakarta.json.JsonObject;
import java.io.Serializable;
import java.text.ParseException;


/**
 * The base class for algorithm names. This class is immutable.
 *
 * <p>Includes constants for the following standard algorithm names:
 *
 * <ul>
 *     <li>{@link #NONE none}
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class Algorithm implements Serializable {


    private static final long serialVersionUID = 1L;


    /**
     * No algorithm (unsecured JOSE object without signature / encryption).
     */
    public static final Algorithm NONE = new Algorithm("none");


    /**
     * The algorithm name.
     */
    private String name;

    /**
     * Creates a new JOSE algorithm name.
     *
     * @param name The algorithm name. Must not be {@code null}.
     */
    public Algorithm(String name) {

        if (name == null) {

            throw new IllegalArgumentException("The algorithm name must not be null");
        }

        this.name = name;

    }


    /**
     * Gets the name of this algorithm.
     *
     * @return The algorithm name.
     */
    public String getName() {

        return name;
    }

    /**
     * Overrides {@code Object.hashCode()}.
     *
     * @return The object hash code.
     */
    @Override
    public int hashCode() {

        return name.hashCode();
    }


    /**
     * Overrides {@code Object.equals()}.
     *
     * @param object The object to compare to.
     * @return {@code true} if the objects have the same value, otherwise
     * {@code false}.
     */
    @Override
    public boolean equals(Object object) {

        return object instanceof Algorithm &&
                this.toString().equals(object.toString());
    }


    /**
     * Returns the string representation of this algorithm.
     *
     * @return The string representation.
     * @see #getName
     */
    @Override
    public String toString() {

        return name;
    }

    /**
     * Parses an algorithm ({@code alg}) parameter from the specified
     * header JSON object. Intended for initial parsing of unsecured
     * (plain), JWS and JWE headers.
     *
     * <p>The algorithm type (none, JWS or JWE) is determined by inspecting
     * the algorithm name for "none" and the presence of an "enc"
     * parameter.
     *
     * @param json The JSON object to parse. Must not be {@code null}.
     * @return The algorithm, an instance of {@link Algorithm#NONE},
     * {@link JWSAlgorithm} or {@link JWEAlgorithm}. {@code null}
     * if not found.
     * @throws ParseException If the {@code alg} parameter couldn't be
     *                        parsed.
     */
    public static Algorithm parseAlgorithm(JsonObject json)
            throws ParseException {

        if (!json.containsKey("alg")) {
            throw new ParseException("Missing \"alg\" in JSON object", 0);
        }

        String algName = json.getString("alg");

        // Infer algorithm type
        if (algName.equals(Algorithm.NONE.getName())) {
            // Plain
            return Algorithm.NONE;
        } else if (json.containsKey("enc")) {
            // JWE
            return JWEAlgorithm.parse(algName);
        } else {
            // JWS
            return JWSAlgorithm.parse(algName);
        }
    }

}
