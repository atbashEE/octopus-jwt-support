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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.nimbus.util.X509CertChainUtils;

import javax.json.JsonObject;
import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Set;


/**
 * JSON Web Key (JWK) metadata.
 *
 * Based on code by Vladimir Dzhuvinov
 */
final class JWKMetadata {


    /**
     * Parses the JWK type.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The key type.
     */
    static KeyType parseKeyType(JsonObject jsonObject) {

        return KeyType.parse(jsonObject.getString("kty"));
    }


    /**
     * Parses the optional public key use.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The key use, {@code null} if not specified or if the key is
     * intended for signing as well as encryption.
     * @throws ParseException If parsing failed.
     */
    static KeyUse parseKeyUse(JsonObject jsonObject)
            throws ParseException {

        if (jsonObject.containsKey("use")) {
            return KeyUse.parse(jsonObject.getString("use"));
        } else {
            return null;
        }
    }


    /**
     * Parses the optional key operations.
     *
     * @param o The JSON object to parse. Must not be {@code null}.
     * @return The key operations, {@code null} if not specified.
     * @throws ParseException If parsing failed.
     */
    static Set<KeyOperation> parseKeyOperations(JsonObject o)
            throws ParseException {

        if (o.containsKey("key_ops")) {
            return KeyOperation.parse(JSONObjectUtils.getStringList(o, "key_ops"));
        } else {
            return null;
        }
    }


    /**
     * Parses the optional algorithm.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The intended JOSE algorithm, {@code null} if not specified.
     */
    static Algorithm parseAlgorithm(JsonObject jsonObject) {

        if (jsonObject.containsKey("alg")) {
            return new Algorithm(jsonObject.getString("alg"));
        } else {
            return null;
        }
    }


    /**
     * Parses the optional key ID.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The key ID, {@code null} if not specified.
     */
    static String parseKeyID(JsonObject jsonObject) {

        if (jsonObject.containsKey("kid")) {
            return jsonObject.getString("kid");
        } else {
            return null;
        }
    }


    /**
     * Parses the optional X.509 certificate URL.
     *
     * @param o The JSON object to parse. Must not be {@code null}.
     * @return The X.509 certificate URL, {@code null} if not specified.
     * @throws ParseException If parsing failed.
     */
    static URI parseX509CertURL(JsonObject o)
            throws ParseException {

        if (o.containsKey("x5u")) {
            return JSONObjectUtils.getURI(o, "x5u");
        } else {
            return null;
        }
    }

    /**
     * Parses the optional X.509 certificate SHA-256 thumbprint.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The X.509 certificate SHA-256 thumbprint, {@code null} if
     * not specified.
     */
    static Base64URLValue parseX509CertSHA256Thumbprint(JsonObject jsonObject) {

        if (jsonObject.containsKey("x5t#S256")) {
            return new Base64URLValue(jsonObject.getString("x5t#S256"));
        } else {
            return null;
        }
    }


    /**
     * Parses the optional X.509 certificate chain.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The X.509 certificate chain (containing at least one
     * certificate) as a unmodifiable list, {@code null} if not
     * specified.
     * @throws ParseException If parsing failed.
     */
    static List<Base64Value> parseX509CertChain(JsonObject jsonObject)
            throws ParseException {

        if (jsonObject.containsKey("x5c")) {
            List<Base64Value> chain = X509CertChainUtils.toBase64List(jsonObject.getJsonArray("x5c"));

            if (chain.isEmpty()) {
                throw new ParseException("The X.509 certificate chain \"x5c\" must not be empty", 0);
            }

            return chain;

        } else {
            return null;
        }
    }
}
