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


import be.atbash.ee.security.octopus.exception.InvalidKeyException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ECUtils;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.BigIntegerUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.*;


/**
 * Public and private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK).
 * This class is immutable.
 *
 * <p>Supported curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256 P-256}
 *     <li>{@link Curve#P_256K P-256K}
 *     <li>{@link Curve#SECP256K1 SECP256K1}
 *     <li>{@link Curve#P_384 P-384}
 *     <li>{@link Curve#P_521 P-512}
 * </ul>
 *
 * <p>Provides EC JWK import from / export to the following standard Java
 * interfaces and classes:
 *
 * <ul>
 *     <li>{@link ECPublicKey}
 *     <li>{@link ECPrivateKey}
 *     <li>{@link PrivateKey} for an EC key in a PKCS#11 store
 *     <li>{@link KeyPair}
 * </ul>
 *
 * <p>Example JSON object representation of a public EC JWK:
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a private EC JWK:
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d"   : "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Use the builder to create a new EC JWK:
 *
 * <pre>
 * ECKey key = new ECKey.Builder(Curve.P_256, x, y)
 * 	.keyUse(KeyUse.SIGNATURE)
 * 	.keyID("1")
 * 	.build();
 * </pre>
 *
 * <p>See <a href="http://en.wikipedia.org/wiki/Elliptic_curve_cryptography">Elliptic curve cryptography (Wikipedia)</a>
 * <p>
 * Based on code by Vladimir Dzhuvinov and Justin Richer
 */
public final class ECKey extends JWK implements AsymmetricJWK, CurveBasedJWK {


    private static final long serialVersionUID = 1L;


    /**
     * Supported EC curves.
     */
    public static final Set<Curve> SUPPORTED_CURVES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(Curve.P_256, Curve.P_256K, Curve.SECP256K1, Curve.P_384, Curve.P_521))
    );


    /**
     * Builder for constructing Elliptic Curve JWKs.
     *
     * <p>Example usage:
     *
     * <pre>
     * ECKey key = new ECKey.Builder(Curve.P521, x, y)
     *     .d(d)
     *     .algorithm(JWSAlgorithm.ES512)
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
         * The public 'x' EC coordinate.
         */
        private final Base64URLValue x;


        /**
         * The public 'y' EC coordinate.
         */
        private final Base64URLValue y;


        /**
         * The private 'd' EC coordinate, optional.
         */
        private Base64URLValue d;


        /**
         * The private EC key, as PKCS#11 handle, optional.
         */
        private PrivateKey priv;


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
         * Creates a new Elliptic Curve JWK builder.
         *
         * @param crv The cryptographic curve. Must not be
         *            {@code null}.
         * @param x   The public 'x' coordinate for the elliptic curve
         *            point. It is represented as the Base64URL
         *            encoding of the coordinate's big endian
         *            representation. Must not be {@code null}.
         * @param y   The public 'y' coordinate for the elliptic curve
         *            point. It is represented as the Base64URL
         *            encoding of the coordinate's big endian
         *            representation. Must not be {@code null}.
         */
        public Builder(Curve crv, Base64URLValue x, Base64URLValue y) {

            if (crv == null) {
                throw new IllegalArgumentException("The curve must not be null");
            }

            this.crv = crv;

            if (x == null) {
                throw new IllegalArgumentException("The 'x' coordinate must not be null");
            }

            this.x = x;

            if (y == null) {
                throw new IllegalArgumentException("The 'y' coordinate must not be null");
            }

            this.y = y;
        }


        /**
         * Creates a new Elliptic Curve JWK builder.
         *
         * @param crv The cryptographic curve. Must not be
         *            {@code null}.
         * @param pub The public EC key to represent. Must not be
         *            {@code null}.
         */
        public Builder(Curve crv, ECPublicKey pub) {

            this(crv,
                    encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
                    encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()));
        }

        public Builder(Curve crv, AtbashKey key) {
            this(crv, getECPublicKey(key));
        }

        private static ECPublicKey getECPublicKey(AtbashKey atbashKey) {
            if (atbashKey.getSecretKeyType().getKeyType() != KeyType.EC) {
                throw new KeyTypeException(atbashKey.getSecretKeyType().getKeyType(), "ECKey creation");
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PUBLIC) {
                throw new KeyTypeException(AsymmetricPart.PUBLIC, "ECKey creation");
            }
            return (ECPublicKey) atbashKey.getKey();
        }

        /**
         * Creates a new Elliptic Curve JWK builder.
         *
         * @param ecJWK The EC JWK to start with. Must not be
         *              {@code null}.
         */
        public Builder(ECKey ecJWK) {

            crv = ecJWK.crv;
            x = ecJWK.x;
            y = ecJWK.y;
            d = ecJWK.d;
            priv = ecJWK.privateKey;
            use = ecJWK.getKeyUse();
            ops = ecJWK.getKeyOperations();
            alg = ecJWK.getAlgorithm();
            kid = ecJWK.getKeyID();
            x5u = ecJWK.getX509CertURL();
            x5t256 = ecJWK.getX509CertSHA256Thumbprint();
            x5c = ecJWK.getX509CertChain();
            ks = ecJWK.getKeyStore();
        }


        /**
         * Sets the private 'd' coordinate for the elliptic curve
         * point. The alternative method is {@link #privateKey}.
         *
         * @param d The private 'd' coordinate. It is represented as
         *          the Base64URL encoding of the coordinate's big
         *          endian representation. {@code null} if not
         *          specified (for a public key).
         * @return This builder.
         */
        public Builder d(Base64URLValue d) {

            this.d = d;
            return this;
        }


        /**
         * Sets the private Elliptic Curve key. The alternative method
         * is {@link #d}.
         *
         * @param priv The private EC key, used to obtain the private
         *             'd' coordinate for the elliptic curve point.
         *             {@code null} if not specified (for a public
         *             key).
         * @return This builder.
         */
        public Builder privateKey(ECPrivateKey priv) {

            if (priv != null) {
                d = encodeCoordinate(priv.getParams().getCurve().getField().getFieldSize(), priv.getS());
            }

            return this;
        }


        /**
         * Sets the private EC key, typically for a key located in a
         * PKCS#11 store that doesn't expose the private key parameters
         * (such as a smart card or HSM).
         *
         * @param priv The private EC key reference. Its algorithm must
         *             be "EC". Must not be {@code null}.
         * @return This builder.
         */
        public Builder privateKey(PrivateKey priv) {

            if (priv instanceof ECPrivateKey) {
                return privateKey((ECPrivateKey) priv);
            }

            if (!"EC".equalsIgnoreCase(priv.getAlgorithm())) {
                throw new IllegalArgumentException("The private key algorithm must be EC");
            }

            this.priv = priv;
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
        public Builder keyUse(KeyUse use) {

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
        public Builder keyOperations(Set<KeyOperation> ops) {

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
        public Builder algorithm(Algorithm alg) {

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
        public Builder keyID(String kid) {

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
        public Builder keyIDFromThumbprint() {

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
        public Builder keyIDFromThumbprint(String hashAlg) {

            // Put mandatory params in sorted order
            LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKIdentifiers.CURVE, crv.toString());
            requiredParams.put(JWKIdentifiers.KEY_TYPE, KeyType.EC.getValue());
            requiredParams.put(JWKIdentifiers.X_COORD, x.toString());
            requiredParams.put(JWKIdentifiers.Y_COORD, y.toString());
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
        public Builder x509CertURL(URI x5u) {

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
        public Builder x509CertSHA256Thumbprint(Base64URLValue x5t256) {

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
        public Builder x509CertChain(List<Base64Value> x5c) {

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
        public Builder keyStore(KeyStore keyStore) {

            ks = keyStore;
            return this;
        }


        /**
         * Builds a new Elliptic Curve JWK.
         *
         * @return The Elliptic Curve JWK.
         * @throws IllegalStateException If the JWK parameters were
         *                               inconsistently specified.
         */
        public ECKey build() {

            try {
                if (d == null && priv == null) {
                    // Public key
                    return new ECKey(crv, x, y, use, ops, alg, kid, x5u, x5t256, x5c, ks);
                }

                if (priv != null) {
                    // PKCS#11 reference to private key
                    return new ECKey(crv, x, y, priv, use, ops, alg, kid, x5u, x5t256, x5c, ks);
                }

                // Public / private key pair with 'd'
                return new ECKey(crv, x, y, d, use, ops, alg, kid, x5u, x5t256, x5c, ks);

            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }


    /**
     * Returns the Base64URL encoding of the specified elliptic curve 'x',
     * 'y' or 'd' coordinate, with leading zero padding up to the specified
     * field size in bits.
     *
     * @param fieldSize  The field size in bits.
     * @param coordinate The elliptic curve coordinate. Must not be
     *                   {@code null}.
     * @return The Base64URL-encoded coordinate, with leading zero padding
     * up to the curve's field size.
     */
    public static Base64URLValue encodeCoordinate(int fieldSize, BigInteger coordinate) {

        byte[] notPadded = BigIntegerUtils.toBytesUnsigned(coordinate);

        int bytesToOutput = (fieldSize + 7) / 8;

        if (notPadded.length >= bytesToOutput) {
            // Greater-than check to prevent exception on malformed
            // key below
            return Base64URLValue.encode(notPadded);
        }

        byte[] padded = new byte[bytesToOutput];

        System.arraycopy(notPadded, 0, padded, bytesToOutput - notPadded.length, notPadded.length);

        return Base64URLValue.encode(padded);
    }

    /**
     * The curve name.
     */
    private Curve crv;


    /**
     * The public 'x' EC coordinate.
     */
    private Base64URLValue x;


    /**
     * The public 'y' EC coordinate.
     */
    private Base64URLValue y;


    /**
     * The private 'd' EC coordinate.
     */
    private Base64URLValue d;


    /**
     * Private PKCS#11 key handle.
     */
    private PrivateKey privateKey;


    /**
     * Ensures the specified 'x' and 'y' public coordinates are on the
     * given curve.
     *
     * @param crv The curve. Must not be {@code null}.
     * @param x   The public 'x' coordinate. Must not be {@code null}.
     * @param y   The public 'y' coordinate. Must not be {@code null}.
     */
    private static void ensurePublicCoordinatesOnCurve(Curve crv, Base64URLValue x, Base64URLValue y) {

        if (!SUPPORTED_CURVES.contains(crv)) {
            throw new IllegalArgumentException("Unknown / unsupported curve: " + crv);
        }

        if (!ECUtils.isPointOnCurve(x.decodeToBigInteger(), y.decodeToBigInteger(), crv.toECParameterSpec())) {
            throw new IllegalArgumentException("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the " + crv + " curve");
        }
    }

    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param x      The public 'x' coordinate for the elliptic curve
     *               point. It is represented as the Base64URL encoding of
     *               the coordinate's big endian representation. Must not
     *               be {@code null}.
     * @param y      The public 'y' coordinate for the elliptic curve
     *               point. It is represented as the Base64URL encoding of
     *               the coordinate's big endian representation. Must not
     *               be {@code null}.
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
    public ECKey(Curve crv, Base64URLValue x, Base64URLValue y,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        super(KeyType.EC, use, ops, alg, kid, x5u, x5t256, x5c, ks);

        if (crv == null) {
            throw new IllegalArgumentException("The curve must not be null");
        }

        this.crv = crv;

        if (x == null) {
            throw new IllegalArgumentException("The 'x' coordinate must not be null");
        }

        this.x = x;

        if (y == null) {
            throw new IllegalArgumentException("The 'y' coordinate must not be null");
        }

        this.y = y;

        ensurePublicCoordinatesOnCurve(crv, x, y);

        ensureMatches(getParsedX509CertChain());

        d = null;

        privateKey = null;
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param x      The public 'x' coordinate for the elliptic curve
     *               point. It is represented as the Base64URL encoding of
     *               the coordinate's big endian representation. Must not
     *               be {@code null}.
     * @param y      The public 'y' coordinate for the elliptic curve
     *               point. It is represented as the Base64URL encoding of
     *               the coordinate's big endian representation. Must not
     *               be {@code null}.
     * @param d      The private 'd' coordinate for the elliptic curve
     *               point. It is represented as the Base64URL encoding of
     *               the coordinate's big endian representation. Must not
     *               be {@code null}.
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
    public ECKey(Curve crv, Base64URLValue x, Base64URLValue y, Base64URLValue d,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        super(KeyType.EC, use, ops, alg, kid, x5u, x5t256, x5c, ks);

        if (crv == null) {
            throw new IllegalArgumentException("The curve must not be null");
        }

        this.crv = crv;

        if (x == null) {
            throw new IllegalArgumentException("The 'x' coordinate must not be null");
        }

        this.x = x;

        if (y == null) {
            throw new IllegalArgumentException("The 'y' coordinate must not be null");
        }

        this.y = y;

        ensurePublicCoordinatesOnCurve(crv, x, y);

        ensureMatches(getParsedX509CertChain());

        if (d == null) {
            throw new IllegalArgumentException("The 'd' coordinate must not be null");
        }

        this.d = d;

        privateKey = null;
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters. The private key is specified by its
     * PKCS#11 handle.
     *
     * @param crv        The cryptographic curve. Must not be {@code null}.
     * @param x          The public 'x' coordinate for the elliptic curve
     *                   point. It is represented as the Base64URL encoding of
     *                   the coordinate's big endian representation. Must not
     *                   be {@code null}.
     * @param y          The public 'y' coordinate for the elliptic curve
     *                   point. It is represented as the Base64URL encoding of
     *                   the coordinate's big endian representation. Must not
     *                   be {@code null}.
     * @param privateKey The private key as a PKCS#11 handle, {@code null} if
     *                   not specified.
     * @param use        The key use, {@code null} if not specified or if the
     *                   key is intended for signing as well as encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param alg        The intended JOSE algorithm for the key, {@code null}
     *                   if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint, {@code null}
     *                   if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     */
    public ECKey(Curve crv, Base64URLValue x, Base64URLValue y, PrivateKey privateKey,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        super(KeyType.EC, use, ops, alg, kid, x5u, x5t256, x5c, ks);

        if (crv == null) {
            throw new IllegalArgumentException("The curve must not be null");
        }

        this.crv = crv;

        if (x == null) {
            throw new IllegalArgumentException("The 'x' coordinate must not be null");
        }

        this.x = x;

        if (y == null) {
            throw new IllegalArgumentException("The 'y' coordinate must not be null");
        }

        this.y = y;

        ensurePublicCoordinatesOnCurve(crv, x, y);

        ensureMatches(getParsedX509CertChain());

        d = null;

        this.privateKey = privateKey;
    }


    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param pub    The public EC key to represent. Must not be
     *               {@code null}.
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
    public ECKey(Curve crv, ECPublicKey pub,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        this(crv,
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param pub    The public EC key to represent. Must not be
     *               {@code null}.
     * @param priv   The private EC key to represent. Must not be
     *               {@code null}.
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
    public ECKey(Curve crv, ECPublicKey pub, ECPrivateKey priv,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        this(crv,
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
                encodeCoordinate(priv.getParams().getCurve().getField().getFieldSize(), priv.getS()),
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters. The private key is specified by its
     * PKCS#11 handle.
     *
     * @param crv    The cryptographic curve. Must not be {@code null}.
     * @param pub    The public EC key to represent. Must not be
     *               {@code null}.
     * @param priv   The private key as a PKCS#11 handle, {@code null} if
     *               not specified.
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
    public ECKey(Curve crv, ECPublicKey pub, PrivateKey priv,
                 KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                 URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                 KeyStore ks) {

        this(
                crv,
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
                encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
                priv,
                use, ops, alg, kid, x5u, x5t256, x5c,
                ks);
    }


    @Override
    public Curve getCurve() {

        return crv;
    }


    /**
     * Gets the public 'x' coordinate for the elliptic curve point.
     *
     * @return The 'x' coordinate. It is represented as the Base64URL
     * encoding of the coordinate's big endian representation.
     */
    public Base64URLValue getX() {

        return x;
    }


    /**
     * Gets the public 'y' coordinate for the elliptic curve point.
     *
     * @return The 'y' coordinate. It is represented as the Base64URL
     * encoding of the coordinate's big endian representation.
     */
    public Base64URLValue getY() {

        return y;
    }


    /**
     * Gets the private 'd' coordinate for the elliptic curve point. It is
     * represented as the Base64URL encoding of the coordinate's big endian
     * representation.
     *
     * @return The 'd' coordinate.  It is represented as the Base64URL
     * encoding of the coordinate's big endian representation.
     * {@code null} if not specified (for a public key).
     */
    public Base64URLValue getD() {

        return d;
    }

    /**
     * Returns a standard {@code java.security.interfaces.ECPublicKey}
     * representation of this Elliptic Curve JWK.
     *
     * @return The public Elliptic Curve key.
     */
    public ECPublicKey toECPublicKey() {

        ECParameterSpec spec = crv.toECParameterSpec();

        if (spec == null) {
            throw new InvalidKeyException("Couldn't get EC parameter spec for curve " + crv);
        }

        ECPoint w = new ECPoint(x.decodeToBigInteger(), y.decodeToBigInteger());

        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, spec);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(JWKIdentifiers.ELLIPTIC_CURVE_KEY_TYPE, BouncyCastleProviderSingleton.getInstance());

            return (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    /**
     * Returns a standard {@code java.security.interfaces.ECPrivateKey}
     * representation of this Elliptic Curve JWK.
     *
     * @return The private Elliptic Curve key, {@code null} if not
     * specified by this JWK.
     */
    public ECPrivateKey toECPrivateKey() {

        if (d == null) {
            // No private 'd' param
            return null;
        }

        ECParameterSpec spec = crv.toECParameterSpec();

        if (spec == null) {
            throw new InvalidKeyException("Couldn't get EC parameter spec for curve " + crv);
        }

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d.decodeToBigInteger(), spec);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(JWKIdentifiers.ELLIPTIC_CURVE_KEY_TYPE, BouncyCastleProviderSingleton.getInstance());

            return (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

            throw new InvalidKeyException(e.getMessage(), e);
        }
    }


    @Override
    public PublicKey toPublicKey() {

        return toECPublicKey();
    }


    @Override
    public PrivateKey toPrivateKey() {

        PrivateKey prv = toECPrivateKey();

        if (prv != null) {
            // Return private EC key with key material
            return prv;
        }

        // Return private EC key as PKCS#11 handle, or null
        return privateKey;
    }

    /**
     * Returns a standard {@code java.security.KeyPair} representation of
     * this Elliptic Curve JWK.
     *
     * @return The Elliptic Curve key pair. The private Elliptic Curve key
     * will be {@code null} if not specified.
     */
    public KeyPair toKeyPair() {

        if (privateKey != null) {
            // Private key as PKCS#11 handle
            return new KeyPair(toECPublicKey(), privateKey);
        } else {
            return new KeyPair(toECPublicKey(), toECPrivateKey());
        }
    }


    @Override
    public boolean matches(X509Certificate cert) {

        ECPublicKey certECKey;
        try {
            certECKey = (ECPublicKey) getParsedX509CertChain().get(0).getPublicKey();
        } catch (ClassCastException ex) {
            return false;
        }
        // Compare Big Ints, base64url encoding may have padding!
        // https://tools.ietf.org/html/rfc7518#section-6.2.1.2
        if (!getX().decodeToBigInteger().equals(certECKey.getW().getAffineX())) {
            return false;
        }
        return getY().decodeToBigInteger().equals(certECKey.getW().getAffineY());
    }


    /**
     * Calls {@link #matches(X509Certificate)} for the first X.509
     * certificate in the specified chain.
     *
     * @param chain The X.509 certificate chain, {@code null} if not
     *              specified.
     * @throws IllegalArgumentException If a certificate chain is specified
     *                                  and the first certificate in it
     *                                  doesn't match.
     */
    private void ensureMatches(List<X509Certificate> chain) {

        if (chain == null) {
            return;
        }

        if (!matches(chain.get(0))) {
            throw new IllegalArgumentException("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
        }
    }


    @Override
    public LinkedHashMap<String, String> getRequiredParams() {

        // Put mandatory params in sorted order
        LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
        requiredParams.put(JWKIdentifiers.CURVE, crv.toString());
        requiredParams.put(JWKIdentifiers.KEY_TYPE, getKeyType().getValue());
        requiredParams.put(JWKIdentifiers.X_COORD, x.toString());
        requiredParams.put(JWKIdentifiers.Y_COORD, y.toString());
        return requiredParams;
    }


    @Override
    public boolean isPrivate() {

        return d != null || privateKey != null;
    }


    @Override
    public int size() {

        ECParameterSpec ecParameterSpec = crv.toECParameterSpec();

        if (ecParameterSpec == null) {
            throw new UnsupportedOperationException("Couldn't determine field size for curve " + crv.getName());
        }

        return ecParameterSpec.getCurve().getField().getFieldSize();
    }


    /**
     * Returns a copy of this Elliptic Curve JWK with any private values
     * removed.
     *
     * @return The copied public Elliptic Curve JWK.
     */
    @Override
    public ECKey toPublicJWK() {

        return new ECKey(
                getCurve(), getX(), getY(),
                getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
                getX509CertURL(), getX509CertSHA256Thumbprint(), getX509CertChain(),
                getKeyStore());
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        // Append EC specific attributes
        result.add(JWKIdentifiers.CURVE, crv.toString());
        result.add(JWKIdentifiers.X_COORD, x.toString());
        result.add(JWKIdentifiers.Y_COORD, y.toString());

        if (d != null) {
            result.add(JWKIdentifiers.ECC_PRIVATE_KEY, d.toString());
        }

        return result;
    }


    /**
     * Parses a public / private Elliptic Curve JWK from the specified JSON
     * object string representation.
     *
     * @param json The JSON object string to parse. Must not be {@code null}.
     * @return The public / private Elliptic Curve JWK.
     * @throws ParseException If the string couldn't be parsed to an
     *                        Elliptic Curve JWK.
     */
    public static ECKey parse(String json)
            throws ParseException {

        return parse(JSONObjectUtils.parse(json));
    }


    /**
     * Parses a public / private Elliptic Curve JWK from the specified JSON
     * object representation.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The public / private Elliptic Curve JWK.
     * @throws ParseException If the JSON object couldn't be parsed to an
     *                        Elliptic Curve JWK.
     */
    public static ECKey parse(JsonObject jsonObject)
            throws ParseException {

        // Check key type
        KeyType kty = JWKMetadata.parseKeyType(jsonObject);

        if (kty != KeyType.EC) {
            throw new ParseException("The key type \"kty\" must be EC", 0);
        }

        // Parse the mandatory parameters first
        String crvValue = JSONObjectUtils.getString(jsonObject, JWKIdentifiers.CURVE);
        if (crvValue == null) {
            throw new ParseException("The cryptographic curve string must not be null or empty", 0);
        }
        Curve crv = Curve.parse(crvValue);

        Base64URLValue x = JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.X_COORD);
        if (x == null) {
            throw new ParseException("The 'x' coordinate must not be null", 0);
        }

        Base64URLValue y = JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.Y_COORD);
        if (y == null) {
            throw new ParseException("The 'y' coordinate must not be null", 0);
        }

        // Get optional private key
        Base64URLValue d = JSONObjectUtils.getBase64URL(jsonObject, JWKIdentifiers.ECC_PRIVATE_KEY);

        try {
            if (d == null) {
                // Public key
                return new ECKey(crv, x, y,
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
                return new ECKey(crv, x, y, d,
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


    /**
     * Parses a public Elliptic Curve JWK from the specified X.509
     * certificate. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * <p>Sets the following JWK parameters:
     *
     * <ul>
     *     <li>The curve is obtained from the subject public key info
     *         algorithm parameters.
     *     <li>The JWK use inferred by {@link KeyUse#from}.
     *     <li>The JWK ID from the X.509 serial number (in base 10).
     *     <li>The JWK X.509 certificate chain (this certificate only).
     *     <li>The JWK X.509 certificate SHA-256 thumbprint.
     * </ul>
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return The public Elliptic Curve JWK.
     */
    public static ECKey parse(X509Certificate cert) {

        if (!(cert.getPublicKey() instanceof ECPublicKey)) {
            throw new JOSEException("The public key of the X.509 certificate is not EC");
        }

        ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

        try {
            JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

            String oid = certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString();

            Curve crv = Curve.forOID(oid);

            if (crv == null) {
                throw new JOSEException("Couldn't determine EC JWK curve for OID " + oid);
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            return new ECKey.Builder(crv, publicKey)
                    .keyUse(KeyUse.from(cert))
                    .keyID(cert.getSerialNumber().toString(10))
                    .x509CertChain(Collections.singletonList(Base64Value.encode(cert.getEncoded())))
                    .x509CertSHA256Thumbprint(Base64URLValue.encode(sha256.digest(cert.getEncoded())))
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't encode x5t parameter: " + e.getMessage(), e);
        } catch (CertificateEncodingException e) {
            throw new JOSEException("Couldn't encode x5c parameter: " + e.getMessage(), e);
        }
    }


    /**
     * Loads a public / private Elliptic Curve JWK from the specified JCA
     * key store. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * @param keyStore The key store. Must not be {@code null}.
     * @param alias    The alias. Must not be {@code null}.
     * @param pin      The pin to unlock the private key if any, empty or
     *                 {@code null} if not required.
     * @return The public / private Elliptic Curve JWK., {@code null} if no
     * key with the specified alias was found.
     * @throws KeyStoreException On a key store exception.
     */
    public static ECKey load(KeyStore keyStore,
                             String alias,
                             char[] pin)
            throws KeyStoreException {

        Certificate cert = keyStore.getCertificate(alias);

        if (!(cert instanceof X509Certificate)) {
            return null;
        }

        X509Certificate x509Cert = (X509Certificate) cert;

        if (!(x509Cert.getPublicKey() instanceof ECPublicKey)) {
            throw new JOSEException("Couldn't load EC JWK: The key algorithm is not EC");
        }

        ECKey ecJWK = ECKey.parse(x509Cert);

        // Let kid=alias
        ecJWK = new ECKey.Builder(ecJWK).keyID(alias).keyStore(keyStore).build();

        // Check for private counterpart
        Key key;
        try {
            key = keyStore.getKey(alias, pin);
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't retrieve private EC key (bad pin?): " + e.getMessage(), e);
        }

        if (key instanceof ECPrivateKey) {
            // Simple file based key store
            return new ECKey.Builder(ecJWK)
                    .privateKey((ECPrivateKey) key)
                    .build();
        } else if (key instanceof PrivateKey && JWKIdentifiers.ELLIPTIC_CURVE_KEY_TYPE.equalsIgnoreCase(key.getAlgorithm())) {
            // PKCS#11 store
            return new ECKey.Builder(ecJWK)
                    .privateKey((PrivateKey) key)
                    .build();
        } else {
            return ecJWK;
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ECKey)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        ECKey ecKey = (ECKey) o;
        return Objects.equals(crv, ecKey.crv) &&
                Objects.equals(x, ecKey.x) &&
                Objects.equals(y, ecKey.y) &&
                Objects.equals(d, ecKey.d) &&
                Objects.equals(privateKey, ecKey.privateKey);
    }


    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), crv, x, y, d, privateKey);
    }
}
