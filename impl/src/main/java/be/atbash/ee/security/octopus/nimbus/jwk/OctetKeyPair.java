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
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;


/**
 * {@link KeyType#OKP Octet key pair} JSON Web Key (JWK), used to represent
 * Edwards-curve keys. This class is immutable.
 *
 * <p>Supported curves:
 *
 * <ul>
 *     <li>{@link Curve#Ed25519 Ed25519}
 *     <li>{@link Curve#Ed448 Ed448}
 *     <li>{@link Curve#X25519 X25519}
 *     <li>{@link Curve#X448 X448}
 * </ul>
 *
 * <p>Example JSON object representation of a public OKP JWK:
 *
 * <pre>
 * {
 *   "kty" : "OKP",
 *   "crv" : "Ed25519",
 *   "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
 *   "use" : "sig",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a private OKP JWK:
 *
 * <pre>
 * {
 *   "kty" : "OKP",
 *   "crv" : "Ed25519",
 *   "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
 *   "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
 *   "use" : "sig",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Use the builder to create a new OKP JWK:
 *
 * <pre>
 * OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, x)
 * 	.keyUse(KeyUse.SIGNATURE)
 * 	.keyID("1")
 * 	.build();
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class OctetKeyPair extends JWK implements AsymmetricJWK, CurveBasedJWK {

    /**
     * Supported Edwards curves.
     */
    public static final Set<Curve> SUPPORTED_CURVES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(Curve.Ed25519, Curve.Ed448, Curve.X25519, Curve.X448))
    );
    private static final String CURVE_MUST_NOT_BE_NULL = "The curve must not be null";
    private static final String X_MUST_NOT_BE_NULL = "The 'x' coordinate must not be null";


    /**
     * Builder for constructing Octet Key Pair JWKs.
     *
     * <p>Example usage:
     *
     * <pre>
     * OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, x)
     *     .d(d)
     *     .algorithm(JWSAlgorithm.EdDSA)
     *     .keyID("1")
     *     .build();
     * </pre>
     */
    public static class Builder {


        /**
         * The curve name.
         */
        private final Curve crv;


        /**
         * The public 'x' parameter.
         */
        private final Base64URLValue x;


        /**
         * The private 'd' parameter, optional.
         */
        private Base64URLValue d;


        /**
         * The key use, optional.
         */
        private KeyUse use;


        /**
         * The key operations, optional.
         */
        private Set<KeyOperation> ops;


        /**
         * The intended JOSE algorithm for the key, optional.
         */
        private Algorithm alg;


        /**
         * The key ID, optional.
         */
        private String kid;


        /**
         * X.509 certificate URL, optional.
         */
        private URI x5u;


        /**
         * X.509 certificate SHA-256 thumbprint, optional.
         */
        private Base64URLValue x5t256;


        /**
         * The X.509 certificate chain, optional.
         */
        private List<Base64Value> x5c;


        /**
         * Reference to the underlying key store, {@code null} if none.
         */
        private KeyStore ks;


        /**
         * Creates a new Octet Key Pair JWK builder.
         *
         * @param crv The cryptographic curve. Must not be
         *            {@code null}.
         * @param x   The public 'x' parameter. Must not be
         *            {@code null}.
         */
        public Builder(Curve crv, Base64URLValue x) {

            if (crv == null) {
                throw new IllegalArgumentException(CURVE_MUST_NOT_BE_NULL);
            }

            this.crv = crv;

            if (x == null) {
                throw new IllegalArgumentException(X_MUST_NOT_BE_NULL);
            }

            this.x = x;
        }


        /**
         * Creates a new Octet Key Pair JWK builder.
         *
         * @param okpJWK The Octet Key Pair to start with. Must not be
         *               {@code null}.
         */
        public Builder(OctetKeyPair okpJWK) {

            crv = okpJWK.crv;
            x = okpJWK.x;
            d = okpJWK.d;
            use = okpJWK.getKeyUse();
            ops = okpJWK.getKeyOperations();
            alg = okpJWK.getAlgorithm();
            kid = okpJWK.getKeyID();
            x5u = okpJWK.getX509CertURL();
            x5t256 = okpJWK.getX509CertSHA256Thumbprint();
            x5c = okpJWK.getX509CertChain();
            ks = okpJWK.getKeyStore();
        }


        /**
         * Sets the private 'd' parameter.
         *
         * @param d The private 'd' parameter, {@code null} if not
         *          specified (for a public key).
         * @return This builder.
         */
        public OctetKeyPair.Builder d(Base64URLValue d) {

            this.d = d;
            return this;
        }


        /**
         * Sets the use ({@code use}) of the JWK.
         *
         * @param use The key use, {@code null} if not specified or if
         *            the key is intended for signing as well as
         *            encryption.
         * @return This builder.
         */
        public OctetKeyPair.Builder keyUse(KeyUse use) {

            this.use = use;
            return this;
        }


        /**
         * Sets the operations ({@code key_ops}) of the JWK.
         *
         * @param ops The key operations, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder keyOperations(Set<KeyOperation> ops) {

            this.ops = ops;
            return this;
        }


        /**
         * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
         *
         * @param alg The intended JOSE algorithm, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder algorithm(Algorithm alg) {

            this.alg = alg;
            return this;
        }

        /**
         * Sets the ID ({@code kid}) of the JWK. The key ID can be used
         * to match a specific key. This can be used, for instance, to
         * choose a key within a {@link JWKSet} during key rollover.
         * The key ID may also correspond to a JWS/JWE {@code kid}
         * header parameter value.
         *
         * @param kid The key ID, {@code null} if not specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder keyID(String kid) {

            this.kid = kid;
            return this;
        }


        /**
         * Sets the ID ({@code kid}) of the JWK to its SHA-256 JWK
         * thumbprint (RFC 7638). The key ID can be used to match a
         * specific key. This can be used, for instance, to choose a
         * key within a {@link JWKSet} during key rollover. The key ID
         * may also correspond to a JWS/JWE {@code kid} header
         * parameter value.
         *
         * @return This builder.
         */
        public OctetKeyPair.Builder keyIDFromThumbprint() {

            return keyIDFromThumbprint("SHA-256");
        }


        /**
         * Sets the ID ({@code kid}) of the JWK to its JWK thumbprint
         * (RFC 7638). The key ID can be used to match a specific key.
         * This can be used, for instance, to choose a key within a
         * {@link JWKSet} during key rollover. The key ID may also
         * correspond to a JWS/JWE {@code kid} header parameter value.
         *
         * @param hashAlg The hash algorithm for the JWK thumbprint
         *                computation. Must not be {@code null}.
         * @return This builder.
         */
        public OctetKeyPair.Builder keyIDFromThumbprint(String hashAlg) {

            // Put mandatory params in sorted order
            LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKIdentifiers.CURVE, crv.toString());
            requiredParams.put(JWKIdentifiers.KEY_TYPE, KeyType.OKP.getValue());
            requiredParams.put(JWKIdentifiers.X_COORD, x.toString());
            kid = ThumbprintUtils.compute(hashAlg, requiredParams).toString();
            return this;
        }


        /**
         * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
         *
         * @param x5u The X.509 certificate URL, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder x509CertURL( URI x5u) {

            this.x5u = x5u;
            return this;
        }

        /**
         * Sets the X.509 certificate SHA-256 thumbprint
         * ({@code x5t#S256}) of the JWK.
         *
         * @param x5t256 The X.509 certificate SHA-256 thumbprint,
         *               {@code null} if not specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder x509CertSHA256Thumbprint(Base64URLValue x5t256) {

            this.x5t256 = x5t256;
            return this;
        }


        /**
         * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
         *
         * @param x5c The X.509 certificate chain as a unmodifiable
         *            list, {@code null} if not specified.
         * @return This builder.
         */
        public OctetKeyPair.Builder x509CertChain(List<Base64Value> x5c) {

            this.x5c = x5c;
            return this;
        }


        /**
         * Sets the underlying key store.
         *
         * @param keyStore Reference to the underlying key store,
         *                 {@code null} if none.
         * @return This builder.
         */
        public OctetKeyPair.Builder keyStore(KeyStore keyStore) {

            this.ks = keyStore;
            return this;
        }


        /**
         * Builds a new Octet Key Pair JWK.
         *
         * @return The Octet Key Pair JWK.
         * @throws IllegalStateException If the JWK parameters were
         *                               inconsistently specified.
         */
        public OctetKeyPair build() {

            try {
                if (d == null) {
                    // Public key
                    return new OctetKeyPair(crv, x, use, ops, alg, kid, x5u, x5t256, x5c, ks);
                }

                // Public / private key pair with 'd'
                return new OctetKeyPair(crv, x, d, use, ops, alg, kid, x5u, x5t256, x5c, ks);

            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }


    /**
     * The curve name.
     */
    private final Curve crv;


    /**
     * The public 'x' parameter.
     */
    private final Base64URLValue x;


    /**
     * The public 'x' parameter, decoded from Base64.
     * Cached for performance and to reduce the risk of side channel attacks
     * against the Base64 decoding procedure.
     */
    private final byte[] decodedX;


    /**
     * The private 'd' parameter.
     */
    private final Base64URLValue d;


    /**
     * The private 'd' parameter, decoded from Base64.
     * Cached for performance and to reduce the risk of side channel attacks
     * against the Base64 decoding procedure.
     */
    private final byte[] decodedD;


    /**
     * Creates a new public Octet Key Pair JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param x      The public 'x' parameter. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public OctetKeyPair(Curve crv, Base64URLValue x,
                        KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                        URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                        KeyStore ks) {

        super(KeyType.OKP, use, ops, alg, kid, x5u, x5t256, x5c, ks);

        if (crv == null) {
            throw new IllegalArgumentException(CURVE_MUST_NOT_BE_NULL);
        }

        if (!SUPPORTED_CURVES.contains(crv)) {
            throw new IllegalArgumentException("Unknown / unsupported curve: " + crv);
        }

        this.crv = crv;

        if (x == null) {
            throw new IllegalArgumentException("The 'x' parameter must not be null");
        }

        this.x = x;
        decodedX = x.decode();

        d = null;
        decodedD = null;
    }


    /**
     * Creates a new public / private Octet Key Pair JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param x      The public 'x' parameter. Must not be {@code null}.
     * @param d      The private 'd' parameter. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public OctetKeyPair(Curve crv, Base64URLValue x, Base64URLValue d,
                        KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                        URI x5u,  Base64URLValue x5t256, List<Base64Value> x5c,
                        KeyStore ks) {

        super(KeyType.OKP, use, ops, alg, kid, x5u, x5t256, x5c, ks);

        if (crv == null) {
            throw new IllegalArgumentException(CURVE_MUST_NOT_BE_NULL);
        }

        if (!SUPPORTED_CURVES.contains(crv)) {
            throw new IllegalArgumentException("Unknown / unsupported curve: " + crv);
        }

        this.crv = crv;

        if (x == null) {
            throw new IllegalArgumentException("The 'x' parameter must not be null");
        }

        this.x = x;
        decodedX = x.decode();

        if (d == null) {
            throw new IllegalArgumentException("The 'd' parameter must not be null");
        }

        this.d = d;
        decodedD = d.decode();
    }


    @Override
    public Curve getCurve() {

        return crv;
    }


    /**
     * Gets the public 'x' parameter.
     *
     * @return The public 'x' parameter.
     */
    public Base64URLValue getX() {

        return x;
    }


    /**
     * Gets the public 'x' parameter, decoded from Base64.
     *
     * @return The public 'x' parameter in bytes.
     */
    public byte[] getDecodedX() {

        return decodedX.clone();
    }


    /**
     * Gets the private 'd' parameter.
     *
     * @return The private 'd' coordinate, {@code null} if not specified
     * (for a public key).
     */
    public Base64URLValue getD() {

        return d;
    }


    /**
     * Gets the private 'd' parameter, decoded from Base64.
     *
     * @return The private 'd' coordinate in bytes, {@code null} if not specified
     * (for a public key).
     */
    public byte[] getDecodedD() {

        return decodedD == null ? null : decodedD.clone();
    }


    @Override
    public PublicKey toPublicKey() {

        Ed25519PublicKeyParameters keyInfo = new Ed25519PublicKeyParameters(x.decode(), 0);

        BCEdDSAPublicKey publicKey = null;
        // BCEdDSAPublicKey constructors are package scope !!!
        Constructor<?>[] constructors = BCEdDSAPublicKey.class.getDeclaredConstructors();
        for (Constructor<?> constructor : constructors) {
            if (AsymmetricKeyParameter.class.isAssignableFrom(constructor.getParameterTypes()[0])) {
                constructor.setAccessible(true);
                try {
                    publicKey = (BCEdDSAPublicKey) constructor.newInstance(keyInfo);
                } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return publicKey;

    }


    @Override
    public PrivateKey toPrivateKey() {

        if (d == null) {
            return null;  // No private part.
        }
        Ed25519PrivateKeyParameters keyInfo = new Ed25519PrivateKeyParameters(d.decode(), 0);

        BCEdDSAPrivateKey privateKey = null;

        // BCEdDSAPrivateKey constructors are package scope !!!
        Constructor<?>[] constructors = BCEdDSAPrivateKey.class.getDeclaredConstructors();
        for (Constructor<?> constructor : constructors) {
            if (AsymmetricKeyParameter.class.isAssignableFrom(constructor.getParameterTypes()[0])) {
                constructor.setAccessible(true);
                try {
                    privateKey = (BCEdDSAPrivateKey) constructor.newInstance(keyInfo);
                } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return privateKey;

    }


    @Override
    public KeyPair toKeyPair() {

        return new KeyPair(toPublicKey(), toPrivateKey());
    }


    @Override
    public boolean matches(X509Certificate cert) {
        // X.509 certs don't support OKP yet
        return false;
    }


    @Override
    public LinkedHashMap<String, String> getRequiredParams() {

        // Put mandatory params in sorted order
        LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
        requiredParams.put(JWKIdentifiers.CURVE, crv.toString());
        requiredParams.put(JWKIdentifiers.KEY_TYPE, getKeyType().getValue());
        requiredParams.put(JWKIdentifiers.X_COORD, x.toString());
        return requiredParams;
    }


    @Override
    public boolean isPrivate() {

        return d != null;
    }


    /**
     * Returns a copy of this Octet Key Pair JWK with any private values
     * removed.
     *
     * @return The copied public Octet Key Pair JWK.
     */
    @Override
    public OctetKeyPair toPublicJWK() {

        return new OctetKeyPair(
                getCurve(), getX(),
                getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
                getX509CertURL(), getX509CertSHA256Thumbprint(), getX509CertChain(),
                getKeyStore());
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        // Append OKP specific attributes
        result.add(JWKIdentifiers.CURVE, crv.toString());
        result.add(JWKIdentifiers.X_COORD, x.toString());

        if (d != null) {
            result.add(JWKIdentifiers.D, d.toString());
        }

        return result;
    }


    @Override
    public int size() {

        return ByteUtils.bitLength(x.decode());
    }


    /**
     * Parses a public / private Octet Key Pair JWK from the specified JSON
     * object string representation.
     *
     * @param value The JSON object string to parse. Must not be {@code null}.
     * @return The public / private Octet Key Pair JWK.
     * @throws ParseException If the string couldn't be parsed to an Octet
     *                        Key Pair JWK.
     */
    public static OctetKeyPair parse(String value)
            throws ParseException {

        return parse(JSONObjectUtils.parse(value));
    }


    /**
     * Parses a public / private Octet Key Pair JWK from the specified JSON
     * object representation.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The public / private Octet Key Pair JWK.
     * @throws ParseException If the JSON object couldn't be parsed to an
     *                        Octet Key Pair JWK.
     */
    public static OctetKeyPair parse(JsonObject jsonObject)
            throws ParseException {

        // Check key type
        KeyType kty = JWKMetadata.parseKeyType(jsonObject);

        if (kty != KeyType.OKP) {
            throw new ParseException("The key type \"kty\" must be OKP", 0);
        }

        // Parse the mandatory parameters first
        String crvString = JSONObjectUtils.getString(jsonObject, JWKIdentifiers.CURVE);
        if (crvString == null || crvString.trim().isEmpty()) {
            throw new ParseException("The cryptographic curve string must not be null or empty", 0);
        }
        Curve crv = Curve.parse(crvString);

        Base64URLValue x = JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.X_COORD);
        if (x == null) {
            throw new ParseException("The 'x' parameter must not be null", 0);
        }

        // Get optional private key
        Base64URLValue d = JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.D);

        try {
            if (d == null) {
                // Public key
                return new OctetKeyPair(crv, x,
                        JWKMetadata.parseKeyUse(jsonObject),
                        JWKMetadata.parseKeyOperations(jsonObject),
                        JWKMetadata.parseAlgorithm(jsonObject),
                        JWKMetadata.parseKeyID(jsonObject),
                        JWKMetadata.parseX509CertURL(jsonObject),
                        JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                        JWKMetadata.parseX509CertChain(jsonObject),
                        null);

            } else {
                // Key pair
                return new OctetKeyPair(crv, x, d,
                        JWKMetadata.parseKeyUse(jsonObject),
                        JWKMetadata.parseKeyOperations(jsonObject),
                        JWKMetadata.parseAlgorithm(jsonObject),
                        JWKMetadata.parseKeyID(jsonObject),
                        JWKMetadata.parseX509CertURL(jsonObject),
                        JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                        JWKMetadata.parseX509CertChain(jsonObject),
                        null);
            }

        } catch (IllegalArgumentException ex) {

            // Conflicting 'use' and 'key_ops'
            throw new ParseException(ex.getMessage(), 0);
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OctetKeyPair)) return false;
        if (!super.equals(o)) return false;
        OctetKeyPair that = (OctetKeyPair) o;
        return Objects.equals(crv, that.crv) &&
                Objects.equals(x, that.x) &&
                Arrays.equals(decodedX, that.decodedX) &&
                Objects.equals(d, that.d) &&
                Arrays.equals(decodedD, that.decodedD);
    }


    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), crv, x, d);
        result = 31 * result + Arrays.hashCode(decodedX);
        result = 31 * result + Arrays.hashCode(decodedD);
        return result;
    }
}
