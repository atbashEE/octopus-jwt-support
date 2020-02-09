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
package be.atbash.ee.security.octopus.nimbus.util;


import java.math.BigInteger;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Base64URL-encoded object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 4648.
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class Base64URLValue extends Base64Value {


    /**
     * Creates a new Base64URL-encoded object.
     *
     * @param base64URL The Base64URL-encoded object value. The value is
     *                  not validated for having characters from the
     *                  Base64URL alphabet. Must not be {@code null}.
     */
    public Base64URLValue(String base64URL) {

        super(base64URL);
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

        return object instanceof Base64URLValue &&
                this.toString().equals(object.toString());
    }


    /**
     * Creates a new Base64URL-encoded object from the specified string.
     *
     * @param base64URL The Base64URL-encoded object value, {@code null} if
     *                  not specified. The value is not validated for
     *                  having characters from the Base64URL alphabet.
     * @return The Base64URL-encoded object, {@code null} if not specified.
     */
    public static Base64URLValue from(String base64URL) {

        if (base64URL == null) {
            return null;
        }

        return new Base64URLValue(base64URL);
    }


    /**
     * Base64URL-encodes the specified byte array.
     *
     * @param bytes The byte array to encode. Must not be {@code null}.
     * @return The resulting Base64URL object.
     */
    public static Base64URLValue encode(byte[] bytes) {

        return new Base64URLValue(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }


    /**
     * Base64URL-encodes the specified big integer, without the sign bit.
     *
     * @param bigInt The big integer to encode. Must not be {@code null}.
     * @return The resulting Base64URL object.
     */
    public static Base64URLValue encode(BigInteger bigInt) {

        return encode(BigIntegerUtils.toBytesUnsigned(bigInt));
    }


    /**
     * Base64URL-encodes the specified string.
     *
     * @param text The string to encode. Must be in the UTF-8 character set
     *             and not {@code null}.
     * @return The resulting Base64URL object.
     */
    public static Base64URLValue encode(String text) {

        return encode(text.getBytes(UTF_8));
    }


    /**
     * Decodes this Base64 object to a byte array.
     *
     * @return The resulting byte array.
     */
    public byte[] decode() {

        return Base64.getUrlDecoder().decode(value.replaceAll("\n", ""));
    }

}
