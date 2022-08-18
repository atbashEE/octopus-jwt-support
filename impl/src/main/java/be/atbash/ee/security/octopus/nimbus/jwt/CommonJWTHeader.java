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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.HeaderParameterType;
import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.util.*;


/**
 * Common class for JWS and JWE headers.
 *
 * <p>Supports all registered header parameters shared by the JWS and JWE
 * specifications:
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
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov
 */
abstract public class CommonJWTHeader extends Header {


    /**
     * JWK Set URL, {@code null} if not specified.
     */
    private final URI jku;


    /**
     * JWK, {@code null} if not specified.
     */
    private final JWK jwk;


    /**
     * X.509 certificate URL, {@code null} if not specified.
     */
    private final URI x5u;


    /**
     * X.509 certificate SHA-256 thumbprint, {@code null} if not specified.
     */
    private final Base64URLValue x5t256;


    /**
     * The X.509 certificate chain corresponding to the key used to sign or
     * encrypt the JWS / JWE object, {@code null} if not specified.
     */
    private final List<Base64Value> x5c;


    /**
     * Key ID, {@code null} if not specified.
     */
    private final String kid;

    /**
     * The registered parameter names.
     */
    static final Set<String> REGISTERED_PARAMETER_NAMES = HeaderParameterType.getCommonJwtHeaderParameters();

    /**
     * Creates a new common JWS and JWE header.
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
     * @param parameters      The parameters, empty map or
     *                        {@code null} if none.
     * @param parsedBase64URL The parsed Base64URL, {@code null} if the
     *                        header is created from scratch.
     */
    protected CommonJWTHeader(Algorithm alg,
                              JOSEObjectType typ,
                              String cty,
                              Set<String> crit,
                              URI jku,
                              JWK jwk,
                              URI x5u,
                              Base64URLValue x5t256,
                              List<Base64Value> x5c,
                              String kid,
                              Map<String, Object> parameters,
                              Base64URLValue parsedBase64URL) {

        super(alg, typ, cty, crit, HeaderParameterType.filterOutRegisteredNames(parameters, REGISTERED_PARAMETER_NAMES), parsedBase64URL);

        this.jku = HeaderParameterType.getParameterValue(HeaderParameterNames.JWK_SET_URL, jku, parameters);
        this.jwk = HeaderParameterType.getParameterValue(HeaderParameterNames.JSON_WEB_KEY, jwk, parameters);
        this.x5u = HeaderParameterType.getParameterValue(HeaderParameterNames.X_509_URL, x5u, parameters);
        this.x5t256 = HeaderParameterType.getParameterValue("x5t256", x5t256, parameters);

        List<Base64Value> temp = HeaderParameterType.getParameterValue(HeaderParameterNames.X_509_CERT_CHAIN, x5c, parameters);
        if (temp != null) {
            // Copy and make unmodifiable
            this.x5c = Collections.unmodifiableList(new ArrayList<>(temp));
        } else {
            this.x5c = null;
        }

        this.kid = HeaderParameterType.getParameterValue(HeaderParameterNames.KEY_ID, kid, parameters);
    }


    /**
     * Gets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
     *
     * @return The JSON Web Key (JWK) Set URL parameter, {@code null} if
     * not specified.
     */
    public URI getJWKURL() {

        return jku;
    }


    /**
     * Gets the JSON Web Key (JWK) ({@code jwk}) parameter.
     *
     * @return The JSON Web Key (JWK) parameter, {@code null} if not
     * specified.
     */
    public JWK getJWK() {

        return jwk;
    }


    /**
     * Gets the X.509 certificate URL ({@code x5u}) parameter.
     *
     * @return The X.509 certificate URL parameter, {@code null} if not
     * specified.
     */
    public URI getX509CertURL() {

        return x5u;
    }

    /**
     * Gets the X.509 certificate SHA-256 thumbprint ({@code x5t#S256})
     * parameter.
     *
     * @return The X.509 certificate SHA-256 thumbprint parameter,
     * {@code null} if not specified.
     */
    public Base64URLValue getX509CertSHA256Thumbprint() {

        return x5t256;
    }


    /**
     * Gets the X.509 certificate chain ({@code x5c}) parameter
     * corresponding to the key used to sign or encrypt the JWS / JWE
     * object.
     *
     * @return The X.509 certificate chain parameter as a unmodifiable
     * list, {@code null} if not specified.
     */
    public List<Base64Value> getX509CertChain() {

        return x5c;
    }


    /**
     * Gets the key ID ({@code kid}) parameter.
     *
     * @return The key ID parameter, {@code null} if not specified.
     */
    public String getKeyID() {

        return kid;
    }


    @Override
    public Set<String> getIncludedParameters() {

        Set<String> includedParameters = super.getIncludedParameters();

        if (jku != null) {
            includedParameters.add(HeaderParameterNames.JWK_SET_URL);
        }

        if (jwk != null) {
            includedParameters.add(HeaderParameterNames.JSON_WEB_KEY);
        }

        if (x5u != null) {
            includedParameters.add(HeaderParameterNames.X_509_URL);
        }

        if (x5t256 != null) {
            includedParameters.add(HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT);
        }

        if (x5c != null && !x5c.isEmpty()) {
            includedParameters.add(HeaderParameterNames.X_509_CERT_CHAIN);
        }

        if (kid != null) {
            includedParameters.add(HeaderParameterNames.KEY_ID);
        }

        return includedParameters;
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        if (jku != null) {
            result.add(HeaderParameterNames.JWK_SET_URL, jku.toString());
        }

        if (jwk != null) {
            result.add(HeaderParameterNames.JSON_WEB_KEY, jwk.toJSONObject());
        }

        if (x5u != null) {
            result.add(HeaderParameterNames.X_509_URL, x5u.toString());
        }

        if (x5t256 != null) {
            result.add(HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT, x5t256.toString());
        }

        if (x5c != null && !x5c.isEmpty()) {
            JsonArrayBuilder x5cArray = Json.createArrayBuilder();
            for (Base64Value base64Value : x5c) {
                x5cArray.add(base64Value.toString());
            }
            result.add(HeaderParameterNames.X_509_CERT_CHAIN, x5cArray);
        }

        if (kid != null) {
            result.add(HeaderParameterNames.KEY_ID, kid);
        }

        return result;
    }

    public static Set<String> getRegisteredParameterNames() {
        HashSet<String> result = new HashSet<>();
        result.addAll(HeaderParameterType.getHeaderParameters());
        result.addAll(HeaderParameterType.getCommonJwtHeaderParameters());
        return result;
    }
}
