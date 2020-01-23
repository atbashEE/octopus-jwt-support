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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.CompressionAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.PlainHeader;
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
import java.util.stream.Collectors;


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
 * <p>The header may also include {@link #getCustomParams custom
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
 * @author Vladimir Dzhuvinov
 * @version 2019-10-04
 */
public final class JWEHeader extends CommonJWTHeader {


    private static final long serialVersionUID = 1L;


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    /*
     * Initialises the registered parameter name set.
     */
    static {
        Set<String> claims = new HashSet<>();

        // FIXME Some of the claims not maintained here but in super classes are removed.
        // This mainly for the filter() method
        // But now functionality is altered since the getRegisteredParameterNames() doesn't return all names anymore
        claims.add("enc");
        claims.add("epk");
        claims.add("zip");
        claims.add("apu");
        claims.add("apv");
        claims.add("p2s");
        claims.add("p2c");
        claims.add("iv");
        claims.add("authTag");

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(claims);
    }

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
        private Map<String, Object> customParams;


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
            customParams = jweHeader.getCustomParams();

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

            customParams = jweHeader.getCustomParams();
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
         * Sets the JSON Web Key (JWK) ({@code jwk}) parameter.
         *
         * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter,
         *            {@code null} if not specified.
         * @return This builder.
         */
        public Builder jwk(JWK jwk) {

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
         * @throws IllegalArgumentException If the specified parameter
         *                                  name matches a registered
         *                                  parameter name.
         */
        public Builder customParam(String name, Object value) {

            if (getRegisteredParameterNames().contains(name)) {
                throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
            }

            if (customParams == null) {
                customParams = new HashMap<>();
            }

            customParams.put(name, value);

            return this;
        }


        /**
         * Sets the custom (non-registered) parameters. The values must
         * be serialisable to a JSON entity, otherwise will be ignored.
         *
         * @param customParameters The custom parameters, empty map or
         *                         {@code null} if none.
         * @return This builder.
         */
        public Builder customParams(Map<String, Object> customParameters) {

            this.customParams = customParameters;
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
                    customParams, parsedBase64URL);
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
     * @param customParams    The custom parameters, empty map or
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
                     Map<String, Object> customParams,
                     Base64URLValue parsedBase64URL) {

        super(alg, typ, cty, crit, jku, jwk, x5u, x5t256, x5c, kid, filter(customParams), parsedBase64URL);

        if (alg.getName().equals(Algorithm.NONE.getName())) {
            throw new IllegalArgumentException("The JWE algorithm cannot be \"none\"");
        }

        if (enc == null) {
            throw new IllegalArgumentException("The encryption method \"enc\" parameter must not be null");
        }

        if (epk != null && epk.isPrivate()) {
            throw new IllegalArgumentException("Ephemeral public key should not be a private key");
        }

        this.enc = enc;

        this.epk = epk;
        this.zip = zip;
        this.apu = apu;
        this.apv = apv;
        if (p2s == null && customParams != null) {
            this.p2s = (Base64URLValue) customParams.get("p2s");  // FIXME We need to checking for this typecast
        } else {
            this.p2s = p2s;
        }
        if (p2c == 0  && customParams != null) {
            // FIXME We need to checking for this typecast
            Integer value = (Integer) customParams.get("p2c");
            if (value != null) {
                // casting fails in case of null.
                this.p2c = value;
            } else {
                this.p2c = 0;
            }
        } else {
            this.p2c = p2c;
        }
        this.iv = iv;
        this.tag = tag;
    }

    /**
     * Filter out the keys which are default supported ones.
     *
     * @param customParams
     * @return
     */
    private static Map<String, Object> filter(Map<String, Object> customParams) {

        if (customParams == null) {
            return new HashMap<>();
        }
        return customParams.entrySet().stream()
                .filter(entry -> !REGISTERED_PARAMETER_NAMES.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

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
                jweHeader.getCustomParams(),
                jweHeader.getParsedBase64URL()
        );
    }


    /**
     * Gets the registered parameter names for JWE headers.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
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
    public Set<String> getIncludedParams() {

        Set<String> includedParameters = super.getIncludedParams();

        if (enc != null) {
            includedParameters.add("enc");
        }

        if (epk != null) {
            includedParameters.add("epk");
        }

        if (zip != null) {
            includedParameters.add("zip");
        }

        if (apu != null) {
            includedParameters.add("apu");
        }

        if (apv != null) {
            includedParameters.add("apv");
        }

        if (p2s != null) {
            includedParameters.add("p2s");
        }

        if (p2c > 0) {
            includedParameters.add("p2c");
        }

        if (iv != null) {
            includedParameters.add("iv");
        }

        if (tag != null) {
            includedParameters.add("tag");
        }

        return includedParameters;
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        if (enc != null) {
            result.add("enc", enc.toString());
        }

        if (epk != null) {
            result.add("epk", epk.toJSONObject());
        }

        if (zip != null) {
            result.add("zip", zip.toString());
        }

        if (apu != null) {
            result.add("apu", apu.toString());
        }

        if (apv != null) {
            result.add("apv", apv.toString());
        }

        if (p2s != null) {
            result.add("p2s", p2s.toString());
        }

        if (p2c > 0) {
            result.add("p2c", p2c);
        }

        if (iv != null) {
            result.add("iv", iv.toString());
        }

        if (tag != null) {
            result.add("tag", tag.toString());
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

        return EncryptionMethod.parse(json.getString("enc"));
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

            if ("alg".equals(name)) {
                // skip
            } else if ("enc".equals(name)) {
                // skip
            } else if ("typ".equals(name)) {
                if (JSONObjectUtils.hasValue(jsonObject, name)) {
                    String typValue = jsonObject.getString(name);
                    if (typValue != null) {
                        header = header.type(new JOSEObjectType(typValue));
                    }
                }
            } else if ("cty".equals(name)) {
                header = header.contentType(jsonObject.getString(name));
            } else if ("crit".equals(name)) {
                List<String> critValues = JSONObjectUtils.getStringList(jsonObject, name);
                if (critValues != null) {
                    header = header.criticalParams(new HashSet<>(critValues));
                }
            } else if ("jku".equals(name)) {
                header = header.jwkURL(JSONObjectUtils.getURI(jsonObject, name));
            } else if ("jwk".equals(name)) {
                if (JSONObjectUtils.hasValue(jsonObject, name)) {
                    JsonObject jwkObject = jsonObject.getJsonObject(name);
                    if (jwkObject != null) {
                        header = header.jwk(JWK.parse(jwkObject));
                    }
                }
            } else if ("x5u".equals(name)) {
                header = header.x509CertURL(JSONObjectUtils.getURI(jsonObject, name));
            } else if ("x5t#S256".equals(name)) {
                header = header.x509CertSHA256Thumbprint(Base64URLValue.from(jsonObject.getString(name)));
            } else if ("x5c".equals(name)) {
                header = header.x509CertChain(X509CertChainUtils.toBase64List(jsonObject.getJsonArray(name)));
            } else if ("kid".equals(name)) {
                header = header.keyID(jsonObject.getString(name));
            } else if ("epk".equals(name)) {
                header = header.ephemeralPublicKey(JWK.parse(jsonObject.getJsonObject(name)));
            } else if ("zip".equals(name)) {
                if (JSONObjectUtils.hasValue(jsonObject, name)) {
                    String zipValue = jsonObject.getString(name);
                    if (zipValue != null) {
                        header = header.compressionAlgorithm(new CompressionAlgorithm(zipValue));
                    }
                }
            } else if ("apu".equals(name)) {
                header = header.agreementPartyUInfo(Base64URLValue.from(jsonObject.getString(name)));
            } else if ("apv".equals(name)) {
                header = header.agreementPartyVInfo(Base64URLValue.from(jsonObject.getString(name)));
            } else if ("p2s".equals(name)) {
                header = header.pbes2Salt(Base64URLValue.from(jsonObject.getString(name)));
            } else if ("p2c".equals(name)) {
                header = header.pbes2Count(jsonObject.getInt(name));
            } else if ("iv".equals(name)) {
                header = header.iv(Base64URLValue.from(jsonObject.getString(name)));
            } else if ("tag".equals(name)) {
                header = header.authTag(Base64URLValue.from(jsonObject.getString(name)));
            } else {
                header = header.customParam(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
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

        return parse(JSONObjectUtils.parse(jsonString), null);
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

        return parse(JSONObjectUtils.parse(jsonString), parsedBase64URL);
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
