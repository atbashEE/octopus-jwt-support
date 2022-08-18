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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.HeaderParameterType;
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
 * JSON Web Encryption (JWE) header. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWE specification:
 *
 * <ul>
 *     <li>alg
 *     <li>enc
 *     <li>epk
 *     <li>zip
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
 *     <li>apu
 *     <li>apv
 *     <li>p2s
 *     <li>p2c
 *     <li>iv
 *     <li>authTag
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParameters custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header:
 *
 * <pre>
 * {
 *   "alg" : "RSA1_5",
 *   "enc" : "A128CBC-HS256"
 * }
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class JWEHeader extends CommonJWTHeader {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES = HeaderParameterType.getJweHeaderParameters();

    /**
     * Builder for constructing JSON Web Encryption (JWE) headers.
     *
     * <p>Example usage:
     *
     * <pre>
     * JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM).
     *                    contentType("text/plain").
     *                    customParam("exp", new Date().getTime()).
     *                    build();
     * </pre>
     */
    public static class Builder {


        /**
         * The JWE algorithm.
         */
        private final JWEAlgorithm alg;


        /**
         * The encryption method.
         */
        private final EncryptionMethod enc;


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
         * JWK Set URL.
         */
        private URI jku;


        /**
         * JWK.
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
         * The ephemeral public key.
         */
        private JWK epk;


        /**
         * The compression algorithm.
         */
        private CompressionAlgorithm zip;


        /**
         * The agreement PartyUInfo.
         */
        private Base64URLValue apu;


        /**
         * The agreement PartyVInfo.
         */
        private Base64URLValue apv;


        /**
         * The PBES2 salt.
         */
        private Base64URLValue p2s;


        /**
         * The PBES2 count.
         */
        private int p2c;


        /**
         * The initialisation vector.
         */
        private Base64URLValue iv;


        /**
         * The authentication authTag.
         */
        private Base64URLValue tag;


        /**
         * Custom header parameters.
         */
        private Map<String, Object> parameters;


        /**
         * The parsed Base64URL.
         */
        private Base64URLValue parsedBase64URL;


        /**
         * Creates a new JWE header builder.
         *
         * @param alg The JWE algorithm ({@code alg}) parameter. Must
         *            not be "none" or {@code null}.
         * @param enc The encryption method. Must not be {@code null}.
         */
        public Builder(JWEAlgorithm alg, EncryptionMethod enc) {

            if (alg.getName().equals(Algorithm.NONE.getName())) {
                throw new IllegalArgumentException("The JWE algorithm \"alg\" cannot be \"none\"");
            }

            this.alg = alg;

            if (enc == null) {
                throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
            }

            this.enc = enc;
        }


        /**
         * Creates a new JWE header builder with the parameters from
         * the specified header.
         *
         * @param jweHeader The JWE header to use. Must not not be
         *                  {@code null}.
         */
        public Builder(JWEHeader jweHeader) {

            this(jweHeader.getAlgorithm(), jweHeader.getEncryptionMethod());

            typ = jweHeader.getType();
            cty = jweHeader.getContentType();
            crit = jweHeader.getCriticalParams();
            parameters = jweHeader.getCustomParameters();

            jku = jweHeader.getJWKURL();
            jwk = jweHeader.getJWK();
            x5u = jweHeader.getX509CertURL();
            x5t256 = jweHeader.getX509CertSHA256Thumbprint();
            x5c = jweHeader.getX509CertChain();
            kid = jweHeader.getKeyID();

            epk = jweHeader.getEphemeralPublicKey();
            zip = jweHeader.getCompressionAlgorithm();
            apu = jweHeader.getAgreementPartyUInfo();
            apv = jweHeader.getAgreementPartyVInfo();
            p2s = jweHeader.getPBES2Salt();
            p2c = jweHeader.getPBES2Count();
            iv = jweHeader.getIV();
            tag = jweHeader.getAuthTag();

            parameters = jweHeader.getCustomParameters();
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
         * ({@code x5t#s256}) parameter.
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
         * Sets the Ephemeral Public Key ({@code epk}) parameter.
         *
         * @param epk The Ephemeral Public Key parameter, {@code null}
         *            if not specified.
         * @return This builder.
         */
        public Builder ephemeralPublicKey(JWK epk) {

            this.epk = epk;
            return this;
        }


        /**
         * Sets the compression algorithm ({@code zip}) parameter.
         *
         * @param zip The compression algorithm parameter, {@code null}
         *            if not specified.
         * @return This builder.
         */
        public Builder compressionAlgorithm(CompressionAlgorithm zip) {

            this.zip = zip;
            return this;
        }


        /**
         * Sets the agreement PartyUInfo ({@code apu}) parameter.
         *
         * @param apu The agreement PartyUInfo parameter, {@code null}
         *            if not specified.
         * @return This builder.
         */
        public Builder agreementPartyUInfo(Base64URLValue apu) {

            this.apu = apu;
            return this;
        }


        /**
         * Sets the agreement PartyVInfo ({@code apv}) parameter.
         *
         * @param apv The agreement PartyVInfo parameter, {@code null}
         *            if not specified.
         * @return This builder.
         */
        public Builder agreementPartyVInfo(Base64URLValue apv) {

            this.apv = apv;
            return this;
        }


        /**
         * Sets the PBES2 salt ({@code p2s}) parameter.
         *
         * @param p2s The PBES2 salt parameter, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder pbes2Salt(Base64URLValue p2s) {

            this.p2s = p2s;
            return this;
        }


        /**
         * Sets the PBES2 count ({@code p2c}) parameter.
         *
         * @param p2c The PBES2 count parameter, zero if not specified.
         *            Must not be negative.
         * @return This builder.
         */
        public Builder pbes2Count(int p2c) {

            if (p2c < 0)
                throw new IllegalArgumentException("The PBES2 count parameter must not be negative");

            this.p2c = p2c;
            return this;
        }


        /**
         * Sets the initialisation vector ({@code iv}) parameter.
         *
         * @param iv The initialisation vector, {@code null} if not
         *           specified.
         * @return This builder.
         */
        public Builder iv(Base64URLValue iv) {

            this.iv = iv;
            return this;
        }


        /**
         * Sets the authentication tag ({@code tag}) parameter.
         *
         * @param tag The authentication tag, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder authTag(Base64URLValue tag) {

            this.tag = tag;
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
         * Builds a new JWE header.
         *
         * @return The JWE header.
         */
        public JWEHeader build() {

            return new JWEHeader(
                    alg, enc, typ, cty, crit,
                    jku, jwk, x5u, x5t256, x5c, kid,
                    epk, zip, apu, apv, p2s, p2c,
                    iv, tag,
                    parameters, parsedBase64URL);
        }
    }


    /**
     * The encryption method ({@code enc}) parameter.
     */
    private final EncryptionMethod enc;


    /**
     * The ephemeral public key ({@code epk}) parameter.
     */
    private final JWK epk;


    /**
     * The compression algorithm ({@code zip}) parameter.
     */
    private final CompressionAlgorithm zip;


    /**
     * The agreement PartyUInfo ({@code apu}) parameter.
     */
    private final Base64URLValue apu;


    /**
     * The agreement PartyVInfo ({@code apv}) parameter.
     */
    private final Base64URLValue apv;


    /**
     * The PBES2 salt ({@code p2s}) parameter.
     */
    private final Base64URLValue p2s;


    /**
     * The PBES2 count ({@code p2c}) parameter.
     */
    private final int p2c;


    /**
     * The initialisation vector ({@code iv}) parameter.
     */
    private final Base64URLValue iv;


    /**
     * The authentication tag ({@code tag}) parameter.
     */
    private final Base64URLValue tag;


    /**
     * Creates a new minimal JSON Web Encryption (JWE) header.
     *
     * <p>Note: Use {@link PlainHeader} to create a header with algorithm
     * {@link Algorithm#NONE none}.
     *
     * @param alg The JWE algorithm parameter. Must not be "none" or
     *            {@code null}.
     * @param enc The encryption method parameter. Must not be
     *            {@code null}.
     */
    @SuppressWarnings("S2259")  // As the rule incorrectly identify a problem.
    public JWEHeader(JWEAlgorithm alg, EncryptionMethod enc) {

        this(
                alg, enc,
                null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, 0,
                null, null,
                null, null);
    }


    /**
     * Creates a new JSON Web Encryption (JWE) header.
     *
     * <p>Note: Use {@link PlainHeader} to create a header with algorithm
     * {@link Algorithm#NONE none}.
     *
     * @param alg             The JWE algorithm ({@code alg}) parameter.
     *                        Must not be "none" or {@code null}.
     * @param enc             The encryption method parameter. Must not be
     *                        {@code null}.
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
     * @param epk             The Ephemeral Public Key ({@code epk})
     *                        parameter, {@code null} if not specified.
     * @param zip             The compression algorithm ({@code zip})
     *                        parameter, {@code null} if not specified.
     * @param apu             The agreement PartyUInfo ({@code apu})
     *                        parameter, {@code null} if not specified.
     * @param apv             The agreement PartyVInfo ({@code apv})
     *                        parameter, {@code null} if not specified.
     * @param p2s             The PBES2 salt ({@code p2s}) parameter,
     *                        {@code null} if not specified.
     * @param p2c             The PBES2 count ({@code p2c}) parameter, zero
     *                        if not specified. Must not be negative.
     * @param iv              The initialisation vector ({@code iv})
     *                        parameter, {@code null} if not specified.
     * @param tag             The authentication tag ({@code tag})
     *                        parameter, {@code null} if not specified.
     * @param parameters    The custom parameters, empty map or
     *                        {@code null} if none.
     * @param parsedBase64URL The parsed Base64URL, {@code null} if the
     *                        header is created from scratch.
     */
    public JWEHeader(Algorithm alg,
                     EncryptionMethod enc,
                     JOSEObjectType typ,
                     String cty,
                     Set<String> crit,
                     URI jku,
                     JWK jwk,
                     URI x5u,
                     Base64URLValue x5t256,
                     List<Base64Value> x5c,
                     String kid,
                     JWK epk,
                     CompressionAlgorithm zip,
                     Base64URLValue apu,
                     Base64URLValue apv,
                     Base64URLValue p2s,
                     int p2c,
                     Base64URLValue iv,
                     Base64URLValue tag,
                     Map<String, Object> parameters,
                     Base64URLValue parsedBase64URL) {

        super(alg, typ, cty, crit, jku, jwk, x5u, x5t256, x5c, kid, HeaderParameterType.filterOutRegisteredNames(parameters, REGISTERED_PARAMETER_NAMES), parsedBase64URL);

        if (getAlgorithm().getName().equals(Algorithm.NONE.getName())) {
            throw new IllegalArgumentException("The JWE algorithm cannot be \"none\"");
        }

        this.enc = HeaderParameterType.getParameterValue(HeaderParameterNames.ENCRYPTION_ALGORITHM, enc, parameters);
        if (this.enc == null) {
            throw new IllegalArgumentException("The encryption method \"" + HeaderParameterNames.ENCRYPTION_ALGORITHM + "\" parameter must not be null");
        }

        this.epk = HeaderParameterType.getParameterValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, epk, parameters);
        if (this.epk != null && this.epk.isPrivate()) {
            throw new IllegalArgumentException("Ephemeral public key should not be a private key");
        }

        this.zip = HeaderParameterType.getParameterValue(HeaderParameterNames.COMPRESSION_ALGORITHM, zip, parameters);
        this.apu = HeaderParameterType.getParameterValue(HeaderParameterNames.AGREEMENT_PARTY_U_INFO, apu, parameters);
        this.apv = HeaderParameterType.getParameterValue(HeaderParameterNames.AGREEMENT_PARTY_V_INFO, apv, parameters);
        this.p2s = HeaderParameterType.getParameterValue(HeaderParameterNames.PBES2_SALT_INPUT, p2s, parameters);

        Integer temp = HeaderParameterType.getParameterValue(HeaderParameterNames.PBES2_COUNT, p2c == 0 ? null : p2c, parameters);
        this.p2c = temp == null ? 0 : temp;

        this.iv = HeaderParameterType.getParameterValue(HeaderParameterNames.INITIALIZATION_VECTOR, iv, parameters);
        this.tag = HeaderParameterType.getParameterValue(HeaderParameterNames.AUTHENTICATION_TAG, tag, parameters);
    }

    /**
     * Deep copy constructor.
     *
     * @param jweHeader The JWE header to copy. Must not be {@code null}.
     */
    public JWEHeader(JWEHeader jweHeader) {

        this(
                jweHeader.getAlgorithm(),
                jweHeader.getEncryptionMethod(),
                jweHeader.getType(),
                jweHeader.getContentType(),
                jweHeader.getCriticalParams(),
                jweHeader.getJWKURL(),
                jweHeader.getJWK(),
                jweHeader.getX509CertURL(),
                jweHeader.getX509CertSHA256Thumbprint(),
                jweHeader.getX509CertChain(),
                jweHeader.getKeyID(),
                jweHeader.getEphemeralPublicKey(),
                jweHeader.getCompressionAlgorithm(),
                jweHeader.getAgreementPartyUInfo(),
                jweHeader.getAgreementPartyVInfo(),
                jweHeader.getPBES2Salt(),
                jweHeader.getPBES2Count(),
                jweHeader.getIV(),
                jweHeader.getAuthTag(),
                jweHeader.getCustomParameters(),
                jweHeader.getParsedBase64URL()
        );
    }


    /**
     * Gets the registered parameter names for JWE headers.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {
        HashSet<String> result = new HashSet<>(Header.getRegisteredParameterNames());
        result.addAll(CommonJWTHeader.getRegisteredParameterNames());
        result.addAll(REGISTERED_PARAMETER_NAMES);
        return result;
    }


    /**
     * Gets the algorithm ({@code alg}) parameter.
     *
     * @return The algorithm parameter.
     */
    public JWEAlgorithm getAlgorithm() {

        return (JWEAlgorithm) super.getAlgorithm();
    }


    /**
     * Gets the encryption method ({@code enc}) parameter.
     *
     * @return The encryption method parameter.
     */
    public EncryptionMethod getEncryptionMethod() {

        return enc;
    }


    /**
     * Gets the Ephemeral Public Key ({@code epk}) parameter.
     *
     * @return The Ephemeral Public Key parameter, {@code null} if not
     * specified.
     */
    public JWK getEphemeralPublicKey() {

        return epk;
    }


    /**
     * Gets the compression algorithm ({@code zip}) parameter.
     *
     * @return The compression algorithm parameter, {@code null} if not
     * specified.
     */
    public CompressionAlgorithm getCompressionAlgorithm() {

        return zip;
    }


    /**
     * Gets the agreement PartyUInfo ({@code apu}) parameter.
     *
     * @return The agreement PartyUInfo parameter, {@code null} if not
     * specified.
     */
    public Base64URLValue getAgreementPartyUInfo() {

        return apu;
    }


    /**
     * Gets the agreement PartyVInfo ({@code apv}) parameter.
     *
     * @return The agreement PartyVInfo parameter, {@code null} if not
     * specified.
     */
    public Base64URLValue getAgreementPartyVInfo() {

        return apv;
    }


    /**
     * Gets the PBES2 salt ({@code p2s}) parameter.
     *
     * @return The PBES2 salt parameter, {@code null} if not specified.
     */
    public Base64URLValue getPBES2Salt() {

        return p2s;
    }


    /**
     * Gets the PBES2 count ({@code p2c}) parameter.
     *
     * @return The PBES2 count parameter, zero if not specified.
     */
    public int getPBES2Count() {

        return p2c;
    }


    /**
     * Gets the initialisation vector ({@code iv}) parameter.
     *
     * @return The initialisation vector, {@code null} if not specified.
     */
    public Base64URLValue getIV() {

        return iv;
    }


    /**
     * Gets the authentication tag ({@code tag}) parameter.
     *
     * @return The authentication tag, {@code null} if not specified.
     */
    public Base64URLValue getAuthTag() {

        return tag;
    }


    @Override
    public Set<String> getIncludedParameters() {

        Set<String> includedParameters = super.getIncludedParameters();

        if (enc != null) {
            includedParameters.add(HeaderParameterNames.ENCRYPTION_ALGORITHM);
        }

        if (epk != null) {
            includedParameters.add(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY);
        }

        if (zip != null) {
            includedParameters.add(HeaderParameterNames.COMPRESSION_ALGORITHM);
        }

        if (apu != null) {
            includedParameters.add(HeaderParameterNames.AGREEMENT_PARTY_U_INFO);
        }

        if (apv != null) {
            includedParameters.add(HeaderParameterNames.AGREEMENT_PARTY_V_INFO);
        }

        if (p2s != null) {
            includedParameters.add(HeaderParameterNames.PBES2_SALT_INPUT);
        }

        if (p2c > 0) {
            includedParameters.add(HeaderParameterNames.PBES2_COUNT);
        }

        if (iv != null) {
            includedParameters.add(HeaderParameterNames.INITIALIZATION_VECTOR);
        }

        if (tag != null) {
            includedParameters.add(HeaderParameterNames.AUTHENTICATION_TAG);
        }

        return includedParameters;
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        if (enc != null) {
            result.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, enc.toString());
        }

        if (epk != null) {
            result.add(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, epk.toJSONObject());
        }

        if (zip != null) {
            result.add(HeaderParameterNames.COMPRESSION_ALGORITHM, zip.toString());
        }

        if (apu != null) {
            result.add(HeaderParameterNames.AGREEMENT_PARTY_U_INFO, apu.toString());
        }

        if (apv != null) {
            result.add(HeaderParameterNames.AGREEMENT_PARTY_V_INFO, apv.toString());
        }

        if (p2s != null) {
            result.add(HeaderParameterNames.PBES2_SALT_INPUT, p2s.toString());
        }

        if (p2c > 0) {
            result.add(HeaderParameterNames.PBES2_COUNT, p2c);
        }

        if (iv != null) {
            result.add(HeaderParameterNames.INITIALIZATION_VECTOR, iv.toString());
        }

        if (tag != null) {
            result.add(HeaderParameterNames.AUTHENTICATION_TAG, tag.toString());
        }

        return result;
    }


    /**
     * Parses an encryption method ({@code enc}) parameter from the
     * specified JWE header JSON object.
     *
     * @param json The JSON object to parse. Must not be {@code null}.
     * @return The encryption method.
     */
    private static EncryptionMethod parseEncryptionMethod(JsonObject json) {

        return EncryptionMethod.parse(JSONObjectUtils.getString(json, HeaderParameterNames.ENCRYPTION_ALGORITHM));
    }


    /**
     * Parses a JWE header from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The JWE header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid JWE header.
     */
    public static JWEHeader parse(JsonObject jsonObject)
            throws ParseException {

        return parse(jsonObject, null);
    }


    /**
     * Parses a JWE header from the specified JSON object.
     *
     * @param jsonObject      The JSON object to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The JWE header.
     * @throws ParseException If the specified JSON object doesn't
     *                        represent a valid JWE header.
     */
    public static JWEHeader parse(JsonObject jsonObject,
                                  Base64URLValue parsedBase64URL)
            throws ParseException {

        // Get the "alg" parameter
        Algorithm alg = Algorithm.parseAlgorithm(jsonObject);

        if (!(alg instanceof JWEAlgorithm)) {
            throw new ParseException("The algorithm \"alg\" header parameter must be for encryption", 0);
        }

        // Get the "enc" parameter
        EncryptionMethod enc = parseEncryptionMethod(jsonObject);

        JWEHeader.Builder header = new Builder((JWEAlgorithm) alg, enc).parsedBase64URL(parsedBase64URL);

        // Parse optional + custom parameters
        for (String name : jsonObject.keySet()) {

            if (HeaderParameterNames.ALGORITHM.equals(name)) {
                // skip
            } else if (HeaderParameterNames.ENCRYPTION_ALGORITHM.equals(name)) {
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
            } else if (HeaderParameterNames.EPHEMERAL_PUBLIC_KEY.equals(name)) {
                header = header.ephemeralPublicKey(JWK.parse(jsonObject.getJsonObject(name)));
            } else if (HeaderParameterNames.COMPRESSION_ALGORITHM.equals(name)) {
                if (JSONObjectUtils.hasValue(jsonObject, name)) {
                    String zipValue = JSONObjectUtils.getString(jsonObject, name);
                    if (zipValue != null) {
                        header = header.compressionAlgorithm(new CompressionAlgorithm(zipValue));
                    }
                }
            } else if (HeaderParameterNames.AGREEMENT_PARTY_U_INFO.equals(name)) {
                header = header.agreementPartyUInfo(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else if (HeaderParameterNames.AGREEMENT_PARTY_V_INFO.equals(name)) {
                header = header.agreementPartyVInfo(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else if (HeaderParameterNames.PBES2_SALT_INPUT.equals(name)) {
                header = header.pbes2Salt(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else if (HeaderParameterNames.PBES2_COUNT.equals(name)) {
                header = header.pbes2Count(jsonObject.getInt(name));
            } else if (HeaderParameterNames.INITIALIZATION_VECTOR.equals(name)) {
                header = header.iv(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else if (HeaderParameterNames.AUTHENTICATION_TAG.equals(name)) {
                header = header.authTag(JSONObjectUtils.getBase64URL(jsonObject, name));
            } else {
                header = header.parameter(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
            }
        }

        return header.build();
    }


    /**
     * Parses a JWE header from the specified JSON object string.
     *
     * @param jsonString The JSON object string to parse. Must not be {@code null}.
     * @return The JWE header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid JWE header.
     */
    public static JWEHeader parse(String jsonString)
            throws ParseException {

        return parse(JSONObjectUtils.parse(jsonString, Header.MAX_HEADER_STRING_LENGTH), null);
    }


    /**
     * Parses a JWE header from the specified JSON object string.
     *
     * @param jsonString      The JSON string to parse. Must not be
     *                        {@code null}.
     * @param parsedBase64URL The original parsed Base64URL, {@code null}
     *                        if not applicable.
     * @return The JWE header.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid JWE header.
     */
    public static JWEHeader parse(String jsonString,
                                  Base64URLValue parsedBase64URL)
            throws ParseException {

        return parse(JSONObjectUtils.parse(jsonString, Header.MAX_HEADER_STRING_LENGTH), parsedBase64URL);
    }


    /**
     * Parses a JWE header from the specified Base64URL.
     *
     * @param base64URL The Base64URL to parse. Must not be {@code null}.
     * @return The JWE header.
     * @throws ParseException If the specified Base64URL doesn't represent
     *                        a valid JWE header.
     */
    public static JWEHeader parse(Base64URLValue base64URL)
            throws ParseException {

        return parse(base64URL.decodeToString(), base64URL);
    }
}
