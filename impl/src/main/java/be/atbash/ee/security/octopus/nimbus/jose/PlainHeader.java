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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.JsonObject;
import java.text.ParseException;
import java.util.*;


/**
 * Unsecured ({@code alg=none}) JOSE header. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the unsecured JOSE object specification:
 *
 * <ul>
 *     <li>alg (set to {@link Algorithm#NONE "none"}).
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * <p>The header may also carry {@link #getCustomParameters custom parameters};
 * these will be serialised and parsed along the registered ones.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "alg" : "none"
 * }
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class PlainHeader extends Header {

    /**
     * Builder for constructing unsecured (plain) headers.
     *
     * <p>Example usage:
     *
     * <pre>
     * PlainHeader header = new PlainHeader.Builder().
     *                      contentType("text/plain").
     *                      customParam("exp", new Date().getTime()).
     *                      build();
     * </pre>
     */
    public static class Builder {


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
         * header parameters.
         */
        private Map<String, Object> parameters;


        /**
         * The parsed Base64URL.
         */
        private Base64URLValue parsedBase64URL;


        /**
         * Creates a new unsecured (plain) header builder.
         */
        public Builder() {

        }


        /**
         * Creates a new unsecured (plain) header builder with the
         * parameters from the specified header.
         *
         * @param plainHeader The unsecured header to use. Must not be
         *                    {@code null}.
         */
        public Builder(PlainHeader plainHeader) {

            typ = plainHeader.getType();
            cty = plainHeader.getContentType();
            crit = plainHeader.getCriticalParams();
            parameters = plainHeader.getCustomParameters();
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

            this.parameters = parameters;
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
         * Builds a new unsecured (plain) header.
         *
         * @return The unsecured header.
         */
        public PlainHeader build() {

            return new PlainHeader(typ, cty, crit, parameters, parsedBase64URL);
        }
    }


    /**
     * Creates a new minimal unsecured (plain) header with algorithm
     * {@link Algorithm#NONE none}.
     */
    public PlainHeader() {

        this(null, null, null, null, null);
    }


    /**
     * Creates a new unsecured (plain) header with algorithm
     * {@link Algorithm#NONE none}.
     *
     * @param typ             The type ({@code typ}) parameter,
     *                        {@code null} if not specified.
     * @param cty             The content type ({@code cty}) parameter,
     *                        {@code null} if not specified.
     * @param crit            The names of the critical header
     *                        ({@code crit}) parameters, empty set or
     *                        {@code null} if none.
     * @param parameters    The custom parameters, empty map or
     *                        {@code null} if none.
     * @param parsedBase64URL The parsed Base64URL, {@code null} if the
     *                        header is created from scratch.
     */
    public PlainHeader(JOSEObjectType typ,
                       String cty,
                       Set<String> crit,
                       Map<String, Object> parameters,
                       Base64URLValue parsedBase64URL) {

        super(Algorithm.NONE, typ, cty, crit, parameters, parsedBase64URL);
    }


    /**
     * Deep copy constructor.
     *
     * @param plainHeader The unsecured header to copy. Must not be
     *                    {@code null}.
     */
    public PlainHeader(PlainHeader plainHeader) {

        this(
                plainHeader.getType(),
                plainHeader.getContentType(),
                plainHeader.getCriticalParams(),
                plainHeader.getCustomParameters(),
                plainHeader.getParsedBase64URL()
        );
    }


    /**
     * Gets the registered parameter names for unsecured headers.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {
        // NO additional parameters
        return Header.getRegisteredParameterNames();
    }


    /**
     * Gets the algorithm ({@code alg}) parameter.
     *
     * @return {@link Algorithm#NONE}.
     */
    @Override
    public Algorithm getAlgorithm() {

        return Algorithm.NONE;
    }


    /**
     * Parses an unsecured header from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The unsecured header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid unsecured header.
     */
    public static PlainHeader parse(JsonObject jsonObject)
            throws ParseException {

        return parse(jsonObject, null);
    }


    /**
     * Parses an unsecured header from the specified JSON object.
     *
     * @param jsonObject      The JSON object to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The unsecured header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid unsecured header.
     */
    public static PlainHeader parse(JsonObject jsonObject,
                                    Base64URLValue parsedBase64URL)
            throws ParseException {

        // Get the "alg" parameter
        Algorithm alg = Algorithm.parseAlgorithm(jsonObject);

        if (alg != Algorithm.NONE) {
            throw new ParseException("The algorithm \"alg\" header parameter must be \"none\"", 0);
        }

        PlainHeader.Builder header = new Builder().parsedBase64URL(parsedBase64URL);

        // Parse optional + custom parameters
        for (String name : jsonObject.keySet()) {

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
            } else {
                header = header.parameter(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
            }
        }

        return header.build();
    }


    /**
     * Parses an unsecured header from the specified JSON string.
     *
     * @param jsonString The JSON string to parse. Must not be
     *                   {@code null}.
     * @return The unsecured header.
     * @throws ParseException If the specified JSON string doesn't
     *                        represent a valid unsecured header.
     */
    public static PlainHeader parse(String jsonString)
            throws ParseException {

        return parse(jsonString, null);
    }


    /**
     * Parses an unsecured header from the specified JSON string.
     *
     * @param jsonString      The JSON string to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The unsecured header.
     * @throws ParseException If the specified JSON string doesn't
     *                        represent a valid unsecured header.
     */
    public static PlainHeader parse(String jsonString,
                                    Base64URLValue parsedBase64URL)
            throws ParseException {

        return parse(JSONObjectUtils.parse(jsonString, Header.MAX_HEADER_STRING_LENGTH), parsedBase64URL);
    }


    /**
     * Parses an unsecured header from the specified Base64URL.
     *
     * @param base64URL The Base64URL to parse. Must not be {@code null}.
     * @return The unsecured header.
     * @throws ParseException If the specified Base64URL doesn't represent
     *                        a valid unsecured header.
     */
    public static PlainHeader parse(Base64URLValue base64URL)
            throws ParseException {

        return parse(base64URL.decodeToString(), base64URL);
    }
}
