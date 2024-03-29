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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.nimbus.jose.*;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwt.CommonJWTHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.nimbus.util.X509CertChainUtils;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Signature (JWS) header. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWS specification:
 *
 * <ul>
 *     <li>alg
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5t#S256
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 *     <li>b64
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header of a JSON Web Signature (JWS) object using the
 * {@link JWSAlgorithm#HS256 HMAC SHA-256 algorithm}:
 *
 * <pre>
 * {
 *   "alg" : "HS256"
 * }
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class JWSHeader extends CommonJWTHeader {


    /**
     * Builder for constructing JSON Web Signature (JWS) headers.
     *
     * <p>Example usage:
     *
     * <pre>
     * JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
     *                    contentType("text/plain").
     *                    parameter("exp", new Date().getTime()).
     *                    build();
     * </pre>
     */
    public static class Builder {


        /**
         * The JWS algorithm.
         */
        private final JWSAlgorithm alg;


        /**
         * The JOSE object type.
         */
        private JOSEObjectType typ;


        /**
         * The content type.
         */
        private String cty;


        /**
         * The critical headers.
         */
        private Set<String> crit;


        /**
         * Public JWK Set URL.
         */
        private URI jku;


        /**
         * Public JWK.
         */
        private JWK jwk;


        /**
         * X.509 certificate URL.
         */
        private URI x5u;

        /**
         * X.509 certificate SHA-256 thumbprint.
         */
        private Base64URLValue x5t256;


        /**
         * The X.509 certificate chain corresponding to the key used to
         * sign the JWS object.
         */
        private List<Base64Value> x5c;


        /**
         * Key ID.
         */
        private String kid;

        /**
         * Base64URL encoding of the payload, the default is
         * {@code true} for standard JWS serialisation.
         */
        private boolean b64 = true;

        /**
         * Custom header parameters.
         */
        private Map<String, Object> parameters;


        /**
         * The parsed Base64URL.
         */
        private Base64URLValue parsedBase64URL;


        /**
         * Creates a new JWS header builder.
         *
         * @param alg The JWS algorithm ({@code alg}) parameter. Must
         *            not be "none" or {@code null}.
         */
        public Builder(JWSAlgorithm alg) {

            if (alg.getName().equals(Algorithm.NONE.getName())) {
                throw new IllegalArgumentException("The JWS algorithm \"alg\" cannot be \"none\"");
            }

            this.alg = alg;
        }


        /**
         * Creates a new JWS header builder with the parameters from
         * the specified header.
         *
         * @param jwsHeader The JWS header to use. Must not not be
         *                  {@code null}.
         */
        public Builder(JWSHeader jwsHeader) {

            this(jwsHeader.getAlgorithm());

            typ = jwsHeader.getType();
            cty = jwsHeader.getContentType();
            crit = jwsHeader.getCriticalParams();

            jku = jwsHeader.getJWKURL();
            jwk = jwsHeader.getJWK();
            x5u = jwsHeader.getX509CertURL();
            x5t256 = jwsHeader.getX509CertSHA256Thumbprint();
            x5c = jwsHeader.getX509CertChain();
            kid = jwsHeader.getKeyID();
            b64 = jwsHeader.isBase64URLEncodePayload();
            parameters = jwsHeader.getCustomParameters();
        }


        /**
         * Sets the type ({@code typ}) parameter.
         *
         * @param typ The type parameter, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder type(JOSEObjectType typ) {

            this.typ = typ;
            return this;
        }


        /**
         * Sets the content type ({@code cty}) parameter.
         *
         * @param cty The content type parameter, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder contentType(String cty) {

            this.cty = cty;
            return this;
        }


        /**
         * Sets the critical header parameters ({@code crit})
         * parameter.
         *
         * @param crit The names of the critical header parameters,
         *             empty set or {@code null} if none.
         * @return This builder.
         */
        public Builder criticalParams(Set<String> crit) {

            this.crit = crit;
            return this;
        }


        /**
         * Sets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
         *
         * @param jku The JSON Web Key (JWK) Set URL parameter,
         *            {@code null} if not specified.
         * @return This builder.
         */
        public Builder jwkURL(URI jku) {

            this.jku = jku;
            return this;
        }


        /**
         * Sets the public JSON Web Key (JWK) ({@code jwk}) parameter.
         *
         * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter,
         *            {@code null} if not specified.
         * @return This builder.
         */
        public Builder jwk(JWK jwk) {
            if (jwk != null && jwk.isPrivate()) {
                throw new IllegalArgumentException("The JWK must be public");
            }

            this.jwk = jwk;
            return this;
        }


        /**
         * Sets the X.509 certificate URL ({@code x5u}) parameter.
         *
         * @param x5u The X.509 certificate URL parameter, {@code null}
         *            if not specified.
         * @return This builder.
         */
        public Builder x509CertURL(URI x5u) {

            this.x5u = x5u;
            return this;
        }


        /**
         * Sets the X.509 certificate SHA-256 thumbprint
         * ({@code x5t#S256}) parameter.
         *
         * @param x5t256 The X.509 certificate SHA-256 thumbprint
         *               parameter, {@code null} if not specified.
         * @return This builder.
         */
        public Builder x509CertSHA256Thumbprint(Base64URLValue x5t256) {

            this.x5t256 = x5t256;
            return this;
        }


        /**
         * Sets the X.509 certificate chain parameter ({@code x5c})
         * corresponding to the key used to sign the JWS object.
         *
         * @param x5c The X.509 certificate chain parameter,
         *            {@code null} if not specified.
         * @return This builder.
         */
        public Builder x509CertChain(List<Base64Value> x5c) {

            this.x5c = x5c;
            return this;
        }


        /**
         * Sets the key ID ({@code kid}) parameter.
         *
         * @param kid The key ID parameter, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder keyID(String kid) {

            this.kid = kid;
            return this;
        }

        /**
         * Sets the Base64URL encode payload ({@code b64}) parameter.
         *
         * @param b64 {@code true} to Base64URL encode the payload
         *            for standard JWS serialisation, {@code false} for
         *            unencoded payload (RFC 7797).
         * @return This builder.
         */
        public Builder base64URLEncodePayload(boolean b64) {

            this.b64 = b64;
            return this;
        }

        /**
         * Sets a custom (non-registered) parameter.
         *
         * @param name  The name of the custom parameter. Must not
         *              match a registered parameter name and must not
         *              be {@code null}.
         * @param value The value of the custom parameter, should map
         *              to a valid JSON entity, {@code null} if not
         *              specified.
         * @return This builder.
         */
        public Builder parameter(String name, Object value) {

            if (HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD.equals(name)) {
                // Backwards compatibility since b64 is now supported parameter.
                base64URLEncodePayload(Boolean.parseBoolean(value.toString()));
                return this;
            }
            if (parameters == null) {
                parameters = new HashMap<>();
            }

            parameters.put(name, value);

            return this;
        }


        /**
         * Sets the custom (non-registered) parameters. The values must
         * be serialisable to a JSON entity, otherwise will be ignored.
         *
         * @param parameters The custom parameters, empty map or
         *                   {@code null} if none.
         * @return This builder.
         */
        public Builder parameters(Map<String, Object> parameters) {

            for (Map.Entry<String, Object> entry : parameters.entrySet()) {
                parameter(entry.getKey(), entry.getValue());
            }

            return this;
        }


        /**
         * Sets the parsed Base64URL.
         *
         * @param base64URL The parsed Base64URL, {@code null} if the
         *                  header is created from scratch.
         * @return This builder.
         */
        public Builder parsedBase64URL(Base64URLValue base64URL) {

            this.parsedBase64URL = base64URL;
            return this;
        }


        /**
         * Builds a new JWS header.
         *
         * @return The JWS header.
         */
        public JWSHeader build() {

            return new JWSHeader(
                    alg, typ, cty, crit,
                    jku, jwk, x5u, x5t256, x5c, kid, b64,
                    parameters, parsedBase64URL);
        }
    }


    /**
     * Creates a new minimal JSON Web Signature (JWS) header.
     *
     * <p>Note: Use {@link PlainHeader} to create a header with algorithm
     * {@link Algorithm#NONE none}.
     *
     * @param alg The JWS algorithm ({@code alg}) parameter. Must not be
     *            "none" or {@code null}.
     */
    public JWSHeader(JWSAlgorithm alg) {

        this(alg, null, null, null, null, null, null, null, null, null, true, null, null);
    }


    /**
     * Creates a new JSON Web Signature (JWS) header.
     *
     * <p>Note: Use {@link PlainHeader} to create a header with algorithm
     * {@link Algorithm#NONE none}.
     *
     * @param alg             The JWS algorithm ({@code alg}) parameter.
     *                        Must not be "none" or {@code null}.
     * @param typ             The type ({@code typ}) parameter,
     *                        {@code null} if not specified.
     * @param cty             The content type ({@code cty}) parameter,
     *                        {@code null} if not specified.
     * @param crit            The names of the critical header
     *                        ({@code crit}) parameters, empty set or
     *                        {@code null} if none.
     * @param jku             The JSON Web Key (JWK) Set URL ({@code jku})
     *                        parameter, {@code null} if not specified.
     * @param jwk             The X.509 certificate URL ({@code jwk})
     *                        parameter, {@code null} if not specified.
     * @param x5u             The X.509 certificate URL parameter
     *                        ({@code x5u}), {@code null} if not specified.
     * @param x5t256          The X.509 certificate SHA-256 thumbprint
     *                        ({@code x5t#S256}) parameter, {@code null} if
     *                        not specified.
     * @param x5c             The X.509 certificate chain ({@code x5c})
     *                        parameter, {@code null} if not specified.
     * @param kid             The key ID ({@code kid}) parameter,
     *                        {@code null} if not specified.
     * @param b64             {@code true} to Base64URL encode the payload
     *                        for standard JWS serialisation, {@code false}
     *                        for unencoded payload (RFC 7797).
     * @param parameters      The custom parameters, empty map or
     *                        {@code null} if none.
     * @param parsedBase64URL The parsed Base64URL, {@code null} if the
     *                        header is created from scratch.
     */
    public JWSHeader(JWSAlgorithm alg,
                     JOSEObjectType typ,
                     String cty,
                     Set<String> crit,
                     URI jku,
                     JWK jwk,
                     URI x5u,
                     Base64URLValue x5t256,
                     List<Base64Value> x5c,
                     String kid,
                     boolean b64,
                     Map<String, Object> parameters,
                     Base64URLValue parsedBase64URL) {

        super(alg, typ, cty, crit, jku, jwk, x5u, x5t256, x5c, kid, parameters, parsedBase64URL);

        if (alg.getName().equals(Algorithm.NONE.getName())) {
            throw new IllegalArgumentException("The JWS algorithm \"alg\" cannot be \"none\"");
        }

        this.b64 = b64;
    }

    /**
     * Base64URL encoding of the payload, {@code true} for standard JWS
     * serialisation, {@code false} for unencoded payload (RFC 7797).
     */
    private final boolean b64;

    /**
     * Deep copy constructor.
     *
     * @param jwsHeader The JWS header to copy. Must not be {@code null}.
     */
    public JWSHeader(JWSHeader jwsHeader) {

        this(
                jwsHeader.getAlgorithm(),
                jwsHeader.getType(),
                jwsHeader.getContentType(),
                jwsHeader.getCriticalParams(),
                jwsHeader.getJWKURL(),
                jwsHeader.getJWK(),
                jwsHeader.getX509CertURL(),
                jwsHeader.getX509CertSHA256Thumbprint(),
                jwsHeader.getX509CertChain(),
                jwsHeader.getKeyID(),
                jwsHeader.isBase64URLEncodePayload(),
                jwsHeader.getCustomParameters(),
                jwsHeader.getParsedBase64URL()
        );
    }


    /**
     * Gets the registered parameter names for JWS headers.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        // No Additional name for JWS.
        Set<String> result = new HashSet<>(CommonJWTHeader.getRegisteredParameterNames());
        result.addAll(Header.getRegisteredParameterNames());
        return result;
    }


    /**
     * Gets the algorithm ({@code alg}) parameter.
     *
     * @return The algorithm parameter.
     */
    @Override
    public JWSAlgorithm getAlgorithm() {

        return (JWSAlgorithm) super.getAlgorithm();
    }

    /**
     * Returns the Base64URL-encode payload ({@code b64}) parameter.
     *
     * @return {@code true} to Base64URL encode the payload for standard
     * JWS serialisation, {@code false} for unencoded payload (RFC
     * 7797).
     */
    public boolean isBase64URLEncodePayload() {

        return b64;
    }


    /**
     * Parses a JWS header from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The JWS header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid JWS header.
     */
    public static JWSHeader parse(JsonObject jsonObject)
            throws ParseException {

        return parse(jsonObject, null);
    }


    /**
     * Parses a JWS header from the specified JSON object.
     *
     * @param jsonObject      The JSON object to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The JWS header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid JWS header.
     */
    public static JWSHeader parse(JsonObject jsonObject,
                                  Base64URLValue parsedBase64URL)
            throws ParseException {

        // Get the "alg" parameter
        Algorithm alg = Algorithm.parseAlgorithm(jsonObject);

        if (!(alg instanceof JWSAlgorithm)) {
            throw new ParseException("The algorithm \"alg\" header parameter must be for signatures", 0);
        }

        JWSHeader.Builder header = new Builder((JWSAlgorithm) alg).parsedBase64URL(parsedBase64URL);

        // Parse optional + custom parameters
        for (final String name : jsonObject.keySet()) {

            if (HeaderParameterNames.ALGORITHM.equals(name)) {
                // skip
            } else if (HeaderParameterNames.TYPE.equals(name)) {
                String typValue = JSONObjectUtils.getString(jsonObject, name);

                if (typValue != null) {
                    header = header.type(new JOSEObjectType(typValue));
                }

            } else if (HeaderParameterNames.CONTENT_TYPE.equals(name)) {
                header = header.contentType(JSONObjectUtils.getString(jsonObject, name));

            } else if (HeaderParameterNames.CRITICAL.equals(name)) {
                List<String> critValues = JSONObjectUtils.getStringList(jsonObject, name);
                if (critValues != null) {
                    header = header.criticalParams(new HashSet<>(critValues));
                }
            } else if (HeaderParameterNames.JWK_SET_URL.equals(name)) {
                header = header.jwkURL(JSONObjectUtils.getURI(jsonObject, name));
            } else if (HeaderParameterNames.JSON_WEB_KEY.equals(name)) {
                if (JSONObjectUtils.hasValue(jsonObject, name)) {
                    JsonObject jwkObject = jsonObject.getJsonObject(name);
                    if (jwkObject != null) {
                        JWK jwk = JWK.parse(jwkObject);
                        if (jwk != null && jwk.isPrivate()) {
                            throw new IllegalArgumentException("Non-public key in jwk header parameter");
                        }
                        header = header.jwk(jwk);
                    }
                }
            } else if (HeaderParameterNames.X_509_URL.equals(name)) {
                header = header.x509CertURL(JSONObjectUtils.getURI(jsonObject, name));
            } else if (HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT.equals(name)) {
                header = header.x509CertSHA256Thumbprint(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else if (HeaderParameterNames.X_509_CERT_CHAIN.equals(name)) {
                header = header.x509CertChain(X509CertChainUtils.toBase64List(jsonObject.getJsonArray(name)));
            } else if (HeaderParameterNames.KEY_ID.equals(name)) {
                header = header.keyID(JSONObjectUtils.getString(jsonObject, name));
            } else {
                header = header.parameter(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
            }
        }

        return header.build();
    }


    /**
     * Parses a JWS header from the specified JSON object string.
     *
     * @param jsonString The JSON string to parse. Must not be
     *                   {@code null}.
     * @return The JWS header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid JWS header.
     */
    public static JWSHeader parse(String jsonString)
            throws ParseException {

        return parse(jsonString, null);
    }


    /**
     * Parses a JWS header from the specified JSON object string.
     *
     * @param jsonString      The JSON string to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The JWS header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid JWS header.
     */
    public static JWSHeader parse(String jsonString,
                                  Base64URLValue parsedBase64URL)
            throws ParseException {

        return parse(JSONObjectUtils.parse(jsonString, Header.MAX_HEADER_STRING_LENGTH), parsedBase64URL);
    }


    /**
     * Parses a JWS header from the specified Base64URL.
     *
     * @param base64URL The Base64URL to parse. Must not be {@code null}.
     * @return The JWS header.
     * @throws ParseException If the specified Base64URL doesn't represent
     *                        a valid JWS header.
     */
    public static JWSHeader parse(Base64URLValue base64URL)
            throws ParseException {

        return parse(base64URL.decodeToString(), base64URL);
    }

    @Override
    public Set<String> getIncludedParameters() {
        Set<String> includedParams = super.getIncludedParameters();
        if (!isBase64URLEncodePayload()) {
            includedParams.add(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD);
        }
        return includedParams;
    }

    @Override
    public JsonObjectBuilder toJSONObject() {
        JsonObjectBuilder result = super.toJSONObject();
        if (!isBase64URLEncodePayload()) {
            result.add(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD, false);
        }
        return result;
    }
}
