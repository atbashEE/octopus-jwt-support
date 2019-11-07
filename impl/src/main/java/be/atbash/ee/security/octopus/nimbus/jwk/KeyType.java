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
package be.atbash.ee.security.octopus.nimbus.jwk;


import java.io.Serializable;


/**
 * Key type. Represents the {@code kty} parameter in a JSON Web Key (JWK).
 * This class is immutable.
 *
 * <p>Includes constants for the following standard key types:
 *
 * <ul>
 *     <li>{@link #EC}
 *     <li>{@link #RSA}
 *     <li>{@link #OCT}
 *     <li>{@link #OKP}
 * </ul>
 *
 * <p>Additional key types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2017-08-23
 */
public final class KeyType implements Serializable {


    private static final long serialVersionUID = 1L;


    /**
     * The key type value.
     */
    private final String value;


    /**
     * Elliptic Curve (DSS) key type (recommended).
     */
    public static final KeyType EC = new KeyType("EC");


    /**
     * RSA (RFC 3447) key type (required).
     */
    public static final KeyType RSA = new KeyType("RSA");


    /**
     * Octet sequence key type (optional).
     */
    public static final KeyType OCT = new KeyType("oct");


    /**
     * Octet key pair (optional).
     */
    public static final KeyType OKP = new KeyType("OKP");


    /**
     * Creates a new key type with the specified value and implementation
     * requirement.
     *
     * @param value The key type value. Values are case sensitive. Must not
     *              be {@code null}.
     */
    public KeyType(String value) {

        if (value == null) {

            throw new IllegalArgumentException("The key type value must not be null");
        }

        this.value = value;

    }


    /**
     * Gets the value of this key type. Values are case sensitive.
     *
     * @return The key type.
     */
    public String getValue() {

        return value;
    }

    /**
     * Overrides {@code Object.hashCode()}.
     *
     * @return The object hash code.
     */
    @Override
    public int hashCode() {

        return value.hashCode();
    }


    /**
     * Overrides {@code Object.equals()}.
     *
     * @param object The object to compare to.
     * @return {@code true} if the objects have the same value, otherwise
     * {@code false}.
     */
    @Override
    public boolean equals(final Object object) {

        return object instanceof KeyType &&
                this.toString().equals(object.toString());
    }


    /**
     * Returns the string representation of this key type.
     *
     * @return The string representation.
     * @see #getValue
     */
    @Override
    public String toString() {

        return value;
    }


    /**
     * Parses a key type from the specified {@code kty} parameter value.
     *
     * @param s The string to parse. Must not be {@code null}.
     * @return The key type (matching standard key type constant, else a
     * newly created one).
     */
    public static KeyType parse(final String s) {

        if (s == null) {
            throw new IllegalArgumentException("The key type to parse must not be null");
        }

        if (s.equals(EC.getValue())) {
            return EC;
        } else if (s.equals(RSA.getValue())) {
            return RSA;
        } else if (s.equals(OCT.getValue())) {
            return OCT;
        } else if (s.equals(OKP.getValue())) {
            return OKP;
        } else {
            return new KeyType(s);
        }
    }

}
