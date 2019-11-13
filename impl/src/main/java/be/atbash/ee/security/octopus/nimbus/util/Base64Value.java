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
package be.atbash.ee.security.octopus.nimbus.util;


import java.io.Serializable;
import java.math.BigInteger;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Base64-encoded object.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-04
 */
public class Base64Value implements /*JSONAware,*/ Serializable {


    private static final long serialVersionUID = 1L;


    /**
     * The Base64 value.
     */
    protected final String value;


    /**
     * Creates a new Base64-encoded object.
     *
     * @param base64 The Base64-encoded object value. The value is not
     *               validated for having characters from a Base64
     *               alphabet. Must not be {@code null}.
     */
    public Base64Value(String base64) {

        if (base64 == null) {

            throw new IllegalArgumentException("The Base64 value must not be null");
        }

        if (base64.endsWith("\n")) {

            value = base64.substring(0, base64.length() - 1);
        } else {
            value = base64;

        }
    }


    /**
     * Decodes this Base64 object to a byte array.
     *
     * @return The resulting byte array.
     */
    public byte[] decode() {

        return Base64.getDecoder().decode(value);
    }


    /**
     * Decodes this Base64 object to an unsigned big integer.
     *
     * <p>Same as {@code new BigInteger(1, base64.decode())}.
     *
     * @return The resulting big integer.
     */
    public BigInteger decodeToBigInteger() {

        return new BigInteger(1, decode());
    }


    /**
     * Decodes this Base64 object to a string.
     *
     * @return The resulting string, in the UTF-8 character set.
     */
    public String decodeToString() {

        return new String(decode(), UTF_8);
    }

    /**
     * Returns a Base64 string representation of this object. The string
     * will be chunked into 76 character blocks separated by CRLF.
     *
     * @return The Base64 string representation, chunked into 76 character
     * blocks separated by CRLF.
     */
    @Override
    public String toString() {

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
    public boolean equals(Object object) {

        return object instanceof Base64Value &&
                this.toString().equals(object.toString());
    }


    /**
     * Creates a new Base64-encoded object from the specified string.
     *
     * @param base64 The Base64-encoded object value, {@code null} if not
     *               specified. The value is not validated for having
     *               characters from the Base64 alphabet.
     * @return The Base64-encoded object, {@code null} if not specified.
     */
    public static Base64Value from(String base64) {

        if (base64 == null) {
            return null;
        }

        return new Base64Value(base64);
    }


    /**
     * Base64-encodes the specified byte array.
     *
     * @param bytes The byte array to encode. Must not be {@code null}.
     * @return The resulting Base64 object.
     */
    public static Base64Value encode(byte[] bytes) {

        return new Base64Value(Base64.getEncoder().encodeToString(bytes));
    }

    /**
     * Base64-encodes the specified string.
     *
     * @param text The string to encode. Must be in the UTF-8 character set
     *             and not {@code null}.
     * @return The resulting Base64 object.
     */
    public static Base64Value encode(String text) {

        return encode(text.getBytes(UTF_8));
    }
}
