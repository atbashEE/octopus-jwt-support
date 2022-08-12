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


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.nimbus.util.X509CertChainUtils;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Set;


/**
 * JSON Web Key (JWK) metadata.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
final class JWKMetadata {


    /**
     * Parses the JWK type.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The key type.
     */
    static KeyType parseKeyType(JsonObject jsonObject) throws ParseException {
        String kty = JSONObjectUtils.getString(jsonObject, JWKIdentifiers.KEY_TYPE);
        if (kty == null || kty.trim().isEmpty()) {

            throw new ParseException("The key type to parse must not be null", 0);
        }
        return KeyType.parse(kty);
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

        if (jsonObject.containsKey(JWKIdentifiers.PUBLIC_KEY_USE) && jsonObject.get(JWKIdentifiers.PUBLIC_KEY_USE).getValueType() == JsonValue.ValueType.STRING) {
            return KeyUse.parse(JSONObjectUtils.getString(jsonObject, JWKIdentifiers.PUBLIC_KEY_USE));
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

        if (o.containsKey(JWKIdentifiers.KEY_OPS)) {
            return KeyOperation.parse(JSONObjectUtils.getStringList(o, JWKIdentifiers.KEY_OPS));
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

        // TODO This pattern is used multiple times
        if (jsonObject.containsKey(JWKIdentifiers.ALGORITHM) && jsonObject.get(JWKIdentifiers.ALGORITHM).getValueType() == JsonValue.ValueType.STRING) {
            return new Algorithm(JSONObjectUtils.getString(jsonObject, JWKIdentifiers.ALGORITHM));
        } else {
            return null;
        }
    }


    /**
     * Parses the optional key ID.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The key ID, {@code null} if not specified ot not a Json String.
     */
    static String parseKeyID(JsonObject jsonObject) {

        return JSONObjectUtils.getString(jsonObject, HeaderParameterNames.KEY_ID);

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

        return JSONObjectUtils.getURI(o, JWKIdentifiers.X_509_URL);

    }

    /**
     * Parses the optional X.509 certificate SHA-256 thumbprint.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The X.509 certificate SHA-256 thumbprint, {@code null} if
     * not specified.
     */
    static Base64URLValue parseX509CertSHA256Thumbprint(JsonObject jsonObject) {

        return JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.X_509_CERT_SHA_256_THUMBPRINT);
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

        if (jsonObject.containsKey(JWKIdentifiers.X_509_CERT_CHAIN) && jsonObject.get(JWKIdentifiers.X_509_CERT_CHAIN).getValueType() == JsonValue.ValueType.ARRAY) {
            List<Base64Value> chain = X509CertChainUtils.toBase64List(jsonObject.getJsonArray(JWKIdentifiers.X_509_CERT_CHAIN));

            if (chain.isEmpty()) {
                throw new ParseException("The X.509 certificate chain \"x5c\" must not be empty", 0);
            }

            return chain;

        } else {
            return null;
        }
    }
}
