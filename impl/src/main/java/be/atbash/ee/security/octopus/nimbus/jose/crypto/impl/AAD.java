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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.IntegerOverflowException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;


/**
 * Additional authenticated data (AAD).
 *
 * <p>See RFC 7518 (JWA), section 5.1, point 14.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class AAD {

    private AAD() {
    }

    /**
     * Computes the Additional Authenticated Data (AAD) for the specified
     * JWE header.
     *
     * @param jweHeader The JWE header. Must not be {@code null}.
     * @return The AAD.
     */
    public static byte[] compute(JWEHeader jweHeader) {

        return compute(jweHeader.toBase64URL());
    }


    /**
     * Computes the Additional Authenticated Data (AAD) for the specified
     * BASE64URL-encoded JWE header.
     *
     * @param encodedJWEHeader The BASE64URL-encoded JWE header. Must not
     *                         be {@code null}.
     * @return The AAD.
     */
    public static byte[] compute(Base64URLValue encodedJWEHeader) {

        return encodedJWEHeader.toString().getBytes(StandardCharsets.US_ASCII);
    }


    /**
     * Computes the bit length of the specified Additional Authenticated
     * Data (AAD). Used in AES/CBC/PKCS5Padding/HMAC-SHA2 encryption.
     *
     * @param aad The Additional Authenticated Data (AAD). Must not be
     *            {@code null}.
     * @return The computed AAD bit length, as a 64 bit big-endian
     * representation (8 byte array).
     * @throws IntegerOverflowException On a integer overflow.
     */
    static byte[] computeLength(byte[] aad)
            throws IntegerOverflowException {

        int bitLength = ByteUtils.safeBitLength(aad);
        return ByteBuffer.allocate(8).putLong(bitLength).array();
    }
}
