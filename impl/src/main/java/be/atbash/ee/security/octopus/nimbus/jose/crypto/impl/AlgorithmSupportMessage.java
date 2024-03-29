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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

import java.util.Collection;


/**
 * Algorithm support messages, intended for JOSE exceptions.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class AlgorithmSupportMessage {


    /**
     * Itemises the specified collection to human readable string.
     *
     * @param collection The collection, with valid {@code toString}
     *                   methods. Must not be {@code null}.
     * @return The string.
     */
    private static String itemize(Collection<?> collection) {

        StringBuilder sb = new StringBuilder();

        Object[] items = collection.toArray();

        for (int i = 0; i < items.length; i++) {

            addDelimiter(sb, i, items.length);

            sb.append(items[i].toString());
        }

        return sb.toString();
    }

    private static void addDelimiter(StringBuilder sb, int idx, int length) {
        if (idx == 0) {
            return;
            // no delimiter
        }
        if (idx < length - 1) {
            sb.append(", ");
        }
        if (idx == length - 1) {
            sb.append(" or ");
        }
    }


    /**
     * Returns a message that the specified JWS algorithm is not supported.
     *
     * @param unsupported The unsupported JWS algorithm. Must not be
     *                    {@code null}.
     * @param supported   The supported JWS algorithms. Must not be
     *                    {@code null}.
     * @return The message.
     */
    public static String unsupportedJWSAlgorithm(JWSAlgorithm unsupported,
                                                 Collection<JWSAlgorithm> supported) {

        return "Unsupported JWS algorithm " + unsupported + ", must be " + itemize(supported);
    }


    /**
     * Returns a message that the specified JWE algorithm is not supported.
     *
     * @param unsupported The unsupported JWE algorithm. Must not be
     *                    {@code null}.
     * @param supported   The supported JWE algorithms. Must not be
     *                    {@code null}.
     * @return The message.
     */
    public static String unsupportedJWEAlgorithm(JWEAlgorithm unsupported,
                                                 Collection<JWEAlgorithm> supported) {

        return "Unsupported JWE algorithm " + unsupported + ", must be " + itemize(supported);
    }


    /**
     * Returns a message that the specified JWE encryption method is not
     * supported.
     *
     * @param unsupported The unsupported JWE encryption method. Must not
     *                    be {@code null}.
     * @param supported   The supported JWE encryption methods. Must not be
     *                    {@code null}.
     * @return The message.
     */
    public static String unsupportedEncryptionMethod(EncryptionMethod unsupported,
                                                     Collection<EncryptionMethod> supported) {

        return "Unsupported JWE encryption method " + unsupported + ", must be " + itemize(supported);
    }


    /**
     * Returns a message that the specified elliptic curve is not
     * supported.
     *
     * @param unsupported The unsupported elliptic curve. Must not be
     *                    {@code null}.
     * @param supported   The supported elliptic curves. Must not be
     *                    {@code null}.
     * @return The message.
     */
    public static String unsupportedEllipticCurve(Curve unsupported,
                                                  Collection<Curve> supported) {

        return "Unsupported elliptic curve " + unsupported + ", must be " + itemize(supported);
    }


    /**
     * Prevents public instantiation.
     */
    private AlgorithmSupportMessage() {

    }
}
