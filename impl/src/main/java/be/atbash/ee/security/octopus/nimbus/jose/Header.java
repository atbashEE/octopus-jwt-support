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


import be.atbash.ee.security.octopus.nimbus.HeaderParameterType;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.Serializable;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * The base abstract class for unsecured ({@code alg=none}), JSON Web Signature
 * (JWS) and JSON Web Encryption (JWE) headers.
 *
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public abstract class Header implements Serializable {


    private static final long serialVersionUID = 1L;

    /**
     * The max allowed string length when parsing a JOSE header (after the
     * BASE64URL decoding). 20K chars should be sufficient to accommodate
     * JOSE headers with an X.509 certificate chain in the {@code x5c}
     * header parameter.
     */
    public static final int MAX_HEADER_STRING_LENGTH = 20_000;


    /**
     * The algorithm ({@code alg}) parameter.
     */
    private final Algorithm alg;


    /**
     * The JOSE object type ({@code typ}) parameter.
     */
    private final JOSEObjectType typ;


    /**
     * The content type ({@code cty}) parameter.
     */
    private final String cty;


    /**
     * The critical headers ({@code crit}) parameter.
     */
    private final Set<String> crit;


    /**
     * Custom header parameters.
     */
    private final Map<String, Object> customParameters;


    /**
     * The original parsed Base64URL, {@code null} if the header was
     * created from scratch.
     */
    private final Base64URLValue parsedBase64URL;

    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES = HeaderParameterType.getHeaderParameters();

    /**
     * Creates a new abstract header.
     *
     * @param alg             The algorithm ({@code alg}) parameter. Must
     *                        not be {@code null}.
     * @param typ             The type ({@code typ}) parameter,
     *                        {@code null} if not specified.
     * @param cty             The content type ({@code cty}) parameter,
     *                        {@code null} if not specified.
     * @param crit            The names of the critical header
     *                        ({@code crit}) parameters, empty set or
     *                        {@code null} if none.
     * @param parameters      The custom parameters, empty map or
     *                        {@code null} if none.
     * @param parsedBase64URL The parsed Base64URL, {@code null} if the
     *                        header is created from scratch.
     */
    protected Header(Algorithm alg,
                     JOSEObjectType typ,
                     String cty,
                     Set<String> crit,
                     Map<String, Object> parameters,
                     Base64URLValue parsedBase64URL) {

        this.alg = HeaderParameterType.getParameterValue(HeaderParameterNames.ALGORITHM, alg, parameters);
        if (this.alg == null) {
            throw new IllegalArgumentException("The algorithm \"" + HeaderParameterNames.ALGORITHM + "\" header parameter must not be null");
        }

        this.typ = HeaderParameterType.getParameterValue(HeaderParameterNames.TYPE, typ, parameters);
        this.cty = HeaderParameterType.getParameterValue(HeaderParameterNames.CONTENT_TYPE, cty, parameters);

        Set<String> temp = HeaderParameterType.getParameterValue(HeaderParameterNames.CRITICAL, crit, parameters);
        if (temp != null) {
            // Copy and make unmodifiable
            this.crit = Collections.unmodifiableSet(new HashSet<>(temp));
        } else {
            this.crit = null;
        }

        this.customParameters = HeaderParameterType.filterOutRegisteredNames(parameters, REGISTERED_PARAMETER_NAMES);

        this.parsedBase64URL = parsedBase64URL;
    }

    /**
     * Deep copy constructor.
     *
     * @param header The header to copy. Must not be {@code null}.
     */
    protected Header(Header header) {

        this(
                header.getAlgorithm(),
                header.getType(),
                header.getContentType(),
                header.getCriticalParams(),
                header.getCustomParameters(),
                header.getParsedBase64URL());
    }


    /**
     * Gets the algorithm ({@code alg}) parameter.
     *
     * @return The algorithm parameter.
     */
    public Algorithm getAlgorithm() {

        return alg;
    }


    /**
     * Gets the type ({@code typ}) parameter.
     *
     * @return The type parameter, {@code null} if not specified.
     */
    public JOSEObjectType getType() {

        return typ;
    }


    /**
     * Gets the content type ({@code cty}) parameter.
     *
     * @return The content type parameter, {@code null} if not specified.
     */
    public String getContentType() {

        return cty;
    }


    /**
     * Gets the critical header parameters ({@code crit}) parameter.
     *
     * @return The names of the critical header parameters, as a
     * unmodifiable set, {@code null} if not specified.
     */
    public Set<String> getCriticalParams() {

        return crit;
    }


    /**
     * Gets a custom (non-registered) parameter.
     *
     * @param name The name of the custom parameter. Must not be
     *             {@code null}.
     * @return The custom parameter, {@code null} if not specified.
     */
    public Object getCustomParameter(String name) {

        return customParameters.get(name);
    }


    /**
     * Gets the custom (non-registered) parameters.
     *
     * @return The custom parameters, as a unmodifiable map, empty map if
     * none.
     */
    public Map<String, Object> getCustomParameters() {

        return customParameters;
    }


    /**
     * Gets the original Base64URL used to create this header.
     *
     * @return The parsed Base64URL, {@code null} if the header was created
     * from scratch.
     */
    public Base64URLValue getParsedBase64URL() {

        return parsedBase64URL;
    }


    /**
     * Gets the names of all included parameters (registered and custom) in
     * the header instance.
     *
     * @return The included parameters.
     */
    public Set<String> getIncludedParameters() {

        Set<String> includedParameters =
                new HashSet<>(getCustomParameters().keySet());

        includedParameters.add(HeaderParameterNames.ALGORITHM);

        if (getType() != null) {
            includedParameters.add(HeaderParameterNames.TYPE);
        }

        if (getContentType() != null) {
            includedParameters.add(HeaderParameterNames.CONTENT_TYPE);
        }

        if (getCriticalParams() != null && !getCriticalParams().isEmpty()) {
            includedParameters.add(HeaderParameterNames.CRITICAL);
        }

        return includedParameters;
    }


    /**
     * Returns a JSON object representation of the header. All custom
     * parameters are included if they serialise to a JSON entity and
     * their names don't conflict with the registered ones.
     *
     * @return The JSON object representation of the header.
     */
    public JsonObjectBuilder toJSONObject() {

        // Include custom parameters, they will be overwritten if their
        // names match specified registered ones
        JsonObjectBuilder result = Json.createObjectBuilder();
        customParameters.forEach((key, value) -> JSONObjectUtils.addValue(result, key, value));

        // Alg is always defined
        result.add(HeaderParameterNames.ALGORITHM, alg.toString());

        if (typ != null) {
            result.add(HeaderParameterNames.TYPE, typ.toString());
        }

        if (cty != null) {
            result.add(HeaderParameterNames.CONTENT_TYPE, cty);
        }

        if (crit != null && !crit.isEmpty()) {
            result.add(HeaderParameterNames.CRITICAL, Json.createArrayBuilder(crit));
        }

        return result;
    }


    /**
     * Returns a JSON string representation of the header. All custom
     * parameters will be included if they serialise to a JSON entity and
     * their names don't conflict with the registered ones.
     *
     * @return The JSON string representation of the header.
     */
    public String toString() {

        return toJSONObject().build().toString();
    }


    /**
     * Returns a Base64URL representation of the header. If the header was
     * parsed always returns the original Base64URL (required for JWS
     * validation and authenticated JWE decryption).
     *
     * @return The original parsed Base64URL representation of the header,
     * or a new Base64URL representation if the header was created
     * from scratch.
     */
    public Base64URLValue toBase64URL() {

        if (parsedBase64URL == null) {

            // Header was created from scratch, return new Base64URL
            return Base64URLValue.encode(toString());

        } else {

            // Header was parsed, return original Base64URL
            return parsedBase64URL;
        }
    }

    public static Set<String> getRegisteredParameterNames() {
        return REGISTERED_PARAMETER_NAMES;
    }

    /**
     * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
     * from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid header.
     */
    public static Header parse(JsonObject jsonObject)
            throws ParseException {

        return parse(jsonObject, null);
    }


    /**
     * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
     * from the specified JSON object.
     *
     * @param jsonObject      The JSON object to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid header.
     */
    public static Header parse(JsonObject jsonObject,
                               Base64URLValue parsedBase64URL)
            throws ParseException {

        Algorithm alg = Algorithm.parseAlgorithm(jsonObject);

        if (alg.equals(Algorithm.NONE)) {

            return PlainHeader.parse(jsonObject, parsedBase64URL);

        } else if (alg instanceof JWSAlgorithm) {

            return JWSHeader.parse(jsonObject, parsedBase64URL);

        } else if (alg instanceof JWEAlgorithm) {

            return JWEHeader.parse(jsonObject, parsedBase64URL);

        } else {

            throw new AssertionError("Unexpected algorithm type: " + alg);
        }
    }

    /**
     * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
     * from the specified JSON object string.
     *
     * @param jsonString The JSON object string to parse. Must not be
     *                   {@code null}.
     * @return The header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid header.
     */
    public static Header parse(String jsonString)
            throws ParseException {

        return parse(jsonString, null);
    }


    /**
     * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
     * from the specified JSON object string.
     *
     * @param jsonString      The JSON object string to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid header.
     */
    public static Header parse(String jsonString,
                               Base64URLValue parsedBase64URL)
            throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse(jsonString, MAX_HEADER_STRING_LENGTH);

        return parse(jsonObject, parsedBase64URL);
    }


    /**
     * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
     * from the specified Base64URL.
     *
     * @param base64URL The Base64URL to parse. Must not be {@code null}.
     * @return The header.
     * @throws ParseException If the specified Base64URL doesn't represent
     *                        a valid header.
     */
    public static Header parse(Base64URLValue base64URL)
            throws ParseException {

        return parse(base64URL.decodeToString(), base64URL);
    }
}