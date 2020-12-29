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
import be.atbash.ee.security.octopus.nimbus.util.*;

import jakarta.json.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAMultiPrimePrivateCrtKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.*;


/**
 * Public and private {@link KeyType#RSA RSA} JSON Web Key (JWK). This class is
 * immutable.
 *
 * <p>Provides RSA JWK import from / export to the following standard Java
 * interfaces and classes:
 *
 * <ul>
 *     <li>{@link RSAPublicKey}
 *     <li>{@link RSAPrivateKey}
 *         <ul>
 *             <li>{@link RSAPrivateCrtKey}
 *             <li>{@link RSAMultiPrimePrivateCrtKey}
 *         </ul>
 *     <li>{@link PrivateKey} for an RSA key in a PKCS#11 store
 *     <li>{@link KeyPair}
 * </ul>
 *
 * <p>Example JSON object representation of a public RSA JWK:
 *
 * <pre>
 * {
 *   "kty" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "alg" : "RS256",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a public and private RSA JWK (with
 * both the first and the second private key representations):
 *
 * <pre>
 * {
 *   "kty" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "d"   : "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9
 *            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij
 *            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d
 *            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz
 *            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz
 *            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
 *   "p"   : "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV
 *            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV
 *            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
 *   "q"   : "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum
 *            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx
 *            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
 *   "dp"  : "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim
 *            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu
 *            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
 *   "dq"  : "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU
 *            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9
 *            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
 *   "qi"  : "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg
 *            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx
 *            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
 *   "alg" : "RS256",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * <p>Use the builder to create a new RSA JWK:
 *
 * <pre>
 * RSAKey key = new RSAKey.Builder(n, e)
 * 	.keyUse(KeyUse.SIGNATURE)
 * 	.keyID("123")
 * 	.build();
 * </pre>
 *
 * <p>See RFC 3447.
 *
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * Based on code by Vladimir Dzhuvinov, Justin Richer and  Cedric Staub
 */
public final class RSAKey extends JWK implements AsymmetricJWK {


    private static final long serialVersionUID = 1L;


    /**
     * Other Primes Info, represents the private {@code oth} parameter of a
     * RSA JWK. This class is immutable.
     */
    public static class OtherPrimesInfo implements Serializable {


        private static final long serialVersionUID = 1L;


        /**
         * The prime factor.
         */
        private final Base64URLValue r;


        /**
         * The factor Chinese Remainder Theorem (CRT) exponent.
         */
        private final Base64URLValue d;


        /**
         * The factor Chinese Remainder Theorem (CRT) coefficient.
         */
        private final Base64URLValue t;


        /**
         * Creates a new JWK Other Primes Info with the specified
         * parameters.
         *
         * @param r The prime factor. Must not be {@code null}.
         * @param d The factor Chinese Remainder Theorem (CRT)
         *          exponent. Must not be {@code null}.
         * @param t The factor Chinese Remainder Theorem (CRT)
         *          coefficient. Must not be {@code null}.
         */
        public OtherPrimesInfo(Base64URLValue r, Base64URLValue d, Base64URLValue t) {

            if (r == null) {

                throw new IllegalArgumentException("The prime factor must not be null");
            }

            this.r = r;

            if (d == null) {

                throw new IllegalArgumentException("The factor CRT exponent must not be null");
            }

            this.d = d;

            if (t == null) {

                throw new IllegalArgumentException("The factor CRT coefficient must not be null");
            }

            this.t = t;
        }


        /**
         * Creates a new JWK Other Primes Info from the specified
         * {@code java.security.spec.RSAOtherPrimeInfo} instance.
         *
         * @param oth The RSA Other Primes Info instance. Must not be
         *            {@code null}.
         */
        public OtherPrimesInfo(RSAOtherPrimeInfo oth) {

            r = Base64URLValue.encode(oth.getPrime());
            d = Base64URLValue.encode(oth.getExponent());
            t = Base64URLValue.encode(oth.getCrtCoefficient());
        }


        /**
         * Gets the prime factor ({@code r}).
         *
         * @return The prime factor.
         */
        public Base64URLValue getPrimeFactor() {

            return r;
        }


        /**
         * Gets factor Chinese Remainder Theorem (CRT) exponent
         * ({@code d}).
         *
         * @return The factor Chinese Remainder Theorem (CRT) exponent.
         */
        public Base64URLValue getFactorCRTExponent() {

            return d;
        }


        /**
         * The factor Chinese Remainder Theorem (CRT) coefficient
         * ({@code t}).
         *
         * @return The factor Chinese Remainder Theorem (CRT)
         * coefficient.
         */
        public Base64URLValue getFactorCRTCoefficient() {

            return t;
        }


        /**
         * Converts the specified array of
         * {@code java.security.spec.RSAOtherPrimeInfo} instances to a
         * list of JWK Other Prime Infos.
         *
         * @param othArray Array of RSA Other Primes Info instances.
         *                 May be be {@code null}.
         * @return The corresponding list of JWK Other Prime Infos, or
         * empty list of the array was {@code null}.
         */
        public static List<OtherPrimesInfo> toList(RSAOtherPrimeInfo[] othArray) {

            List<OtherPrimesInfo> list = new ArrayList<>();

            if (othArray == null) {

                // Return empty list
                return list;
            }

            for (RSAOtherPrimeInfo oth : othArray) {

                list.add(new OtherPrimesInfo(oth));
            }

            return list;
        }
    }


    /**
     * Builder for constructing RSA JWKs.
     *
     * <p>Example usage:
     *
     * <pre>
     * RSAKey key = new RSAKey.Builder(n, e).
     *              privateExponent(d).
     *              algorithm(JWSAlgorithm.RS512).
     *              keyID("456").
     *              build();
     * </pre>
     */
    public static class Builder {


        // Public RSA params

        /**
         * The modulus value for the RSA key.
         */
        private final Base64URLValue n;


        /**
         * The public exponent of the RSA key.
         */
        private final Base64URLValue e;


        // Private RSA params, 1st representation

        /**
         * The private exponent of the RSA key.
         */
        private Base64URLValue d;


        // Private RSA params, 2nd representation

        /**
         * The first prime factor of the private RSA key.
         */
        private Base64URLValue p;


        /**
         * The second prime factor of the private RSA key.
         */
        private Base64URLValue q;


        /**
         * The first factor Chinese Remainder Theorem exponent of the
         * private RSA key.
         */
        private Base64URLValue dp;


        /**
         * The second factor Chinese Remainder Theorem exponent of the
         * private RSA key.
         */
        private Base64URLValue dq;


        /**
         * The first Chinese Remainder Theorem coefficient of the private RSA
         * key.
         */
        private Base64URLValue qi;


        /**
         * The other primes information of the private RSA key, should
         * they exist. When only two primes have been used (the normal
         * case), this parameter MUST be omitted. When three or more
         * primes have been used, the number of array elements MUST be
         * the number of primes used minus two.
         */
        private List<OtherPrimesInfo> oth;


        // Private RSA key, as PKCS#11 handle

        /**
         * The private RSA key, as PKCS#11 handle.
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
        private KeyStore keystore;


        /**
         * Creates a new RSA JWK builder.
         *
         * @param n The the modulus value for the public RSA key. It is
         *          represented as the Base64URL encoding of value's
         *          big endian representation. Must not be
         *          {@code null}.
         * @param e The exponent value for the public RSA key. It is
         *          represented as the Base64URL encoding of value's
         *          big endian representation. Must not be
         *          {@code null}.
         */
        public Builder(Base64URLValue n, Base64URLValue e) {

            // Ensure the public params are defined

            if (n == null) {
                throw new IllegalArgumentException("The modulus value must not be null");
            }

            this.n = n;


            if (e == null) {
                throw new IllegalArgumentException("The public exponent value must not be null");
            }

            this.e = e;
        }


        /**
         * Creates a new RSA JWK builder.
         *
         * @param pub The public RSA key to represent. Must not be
         *            {@code null}.
         */
        public Builder(RSAPublicKey pub) {

            n = Base64URLValue.encode(pub.getModulus());
            e = Base64URLValue.encode(pub.getPublicExponent());
        }

        /**
         * Creates a new RSA JWK builder.
         *
         * @param rsaJWK The RSA JWK to start with. Must not be
         *               {@code null}.
         */
        public Builder(RSAKey rsaJWK) {

            n = rsaJWK.n;
            e = rsaJWK.e;
            d = rsaJWK.d;
            p = rsaJWK.p;
            q = rsaJWK.q;
            dp = rsaJWK.dp;
            dq = rsaJWK.dq;
            qi = rsaJWK.qi;
            oth = rsaJWK.oth;
            priv = rsaJWK.privateKey;
            use = rsaJWK.getKeyUse();
            ops = rsaJWK.getKeyOperations();
            alg = rsaJWK.getAlgorithm();
            kid = rsaJWK.getKeyID();
            x5u = rsaJWK.getX509CertURL();
            x5t256 = rsaJWK.getX509CertSHA256Thumbprint();
            x5c = rsaJWK.getX509CertChain();
            keystore = rsaJWK.getKeyStore();
        }

        /**
         * Creates a new RSA JWK builder.
         *
         * @param atbashKey The RSA public key as AtbashKey top start with.
         */
        public Builder(AtbashKey atbashKey) {
            this(getRSAPublicKey(atbashKey));
        }

        private static RSAPublicKey getRSAPublicKey(AtbashKey atbashKey) {
            if (atbashKey.getSecretKeyType().getKeyType() != KeyType.RSA) {
                throw new KeyTypeException(atbashKey.getSecretKeyType().getKeyType(), "RSAKey creation");
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PUBLIC) {
                throw new KeyTypeException(AsymmetricPart.PUBLIC, "RSAKey creation");
            }
            return (RSAPublicKey) atbashKey.getKey();
        }

        /**
         * Sets the private exponent ({@code d}) of the RSA key.
         *
         * @param d The private RSA key exponent. It is represented as
         *          the Base64URL encoding of the value's big endian
         *          representation. {@code null} if not specified (for
         *          a public key or a private key using the second
         *          representation only).
         * @return This builder.
         */
        public Builder privateExponent(Base64URLValue d) {

            this.d = d;
            return this;
        }


        /**
         * Sets the private RSA key, using the first representation.
         *
         * @param priv The private RSA key, used to obtain the private
         *             exponent ({@code d}). Must not be {@code null}.
         * @return This builder.
         */
        public Builder privateKey(RSAPrivateKey priv) {

            if (priv instanceof RSAPrivateCrtKey) {
                return privateKey((RSAPrivateCrtKey) priv);
            } else if (priv instanceof RSAMultiPrimePrivateCrtKey) {
                return privateKey((RSAMultiPrimePrivateCrtKey) priv);
            } else {
                d = Base64URLValue.encode(priv.getPrivateExponent());
                return this;
            }
        }


        /**
         * Sets the private RSA key, typically for a key located in a
         * PKCS#11 store that doesn't expose the private key parameters
         * (such as a smart card or HSM).
         *
         * @param priv The private RSA key reference. Its algorithm
         *             must be "RSA". Must not be {@code null}.
         * @return This builder.
         */
        public Builder privateKey(PrivateKey priv) {
            if (priv instanceof RSAPrivateKey) {
                return privateKey((RSAPrivateKey) priv);
            }

            if (!"RSA".equalsIgnoreCase(priv.getAlgorithm())) {
                throw new IllegalArgumentException("The private key algorithm must be RSA");
            }

            this.priv = priv;
            return this;
        }


        /**
         * Sets the first prime factor ({@code p}) of the private RSA
         * key.
         *
         * @param p The RSA first prime factor. It is represented as
         *          the Base64URL encoding of the value's big endian
         *          representation. {@code null} if not specified (for
         *          a public key or a private key using the first
         *          representation only).
         * @return This builder.
         */
        public Builder firstPrimeFactor(Base64URLValue p) {

            this.p = p;
            return this;
        }


        /**
         * Sets the second prime factor ({@code q}) of the private RSA
         * key.
         *
         * @param q The RSA second prime factor. It is represented as
         *          the Base64URL encoding of the value's big endian
         *          representation. {@code null} if not specified (for
         *          a public key or a private key using the first
         *          representation only).
         * @return This builder.
         */
        public Builder secondPrimeFactor(Base64URLValue q) {

            this.q = q;
            return this;
        }


        /**
         * Sets the first factor Chinese Remainder Theorem (CRT)
         * exponent ({@code dp}) of the private RSA key.
         *
         * @param dp The RSA first factor CRT exponent. It is
         *           represented as the Base64URL encoding of the
         *           value's big endian representation. {@code null}
         *           if not specified (for a public key or a private
         *           key using the first representation only).
         * @return This builder.
         */
        public Builder firstFactorCRTExponent(Base64URLValue dp) {

            this.dp = dp;
            return this;
        }


        /**
         * Sets the second factor Chinese Remainder Theorem (CRT)
         * exponent ({@code dq}) of the private RSA key.
         *
         * @param dq The RSA second factor CRT exponent. It is
         *           represented as the Base64URL encoding of the
         *           value's big endian representation. {@code null} if
         *           not specified (for a public key or a private key
         *           using the first representation only).
         * @return This builder.
         */
        public Builder secondFactorCRTExponent(Base64URLValue dq) {

            this.dq = dq;
            return this;
        }


        /**
         * Sets the first Chinese Remainder Theorem (CRT) coefficient
         * ({@code qi}) of the private RSA key.
         *
         * @param qi The RSA first CRT coefficient. It is represented
         *           as the Base64URL encoding of the value's big
         *           endian representation. {@code null} if not
         *           specified (for a public key or a private key using
         *           the first representation only).
         * @return This builder.
         */
        public Builder firstCRTCoefficient(Base64URLValue qi) {

            this.qi = qi;
            return this;
        }


        /**
         * Sets the other primes information ({@code oth}) for the
         * private RSA key, should they exist.
         *
         * @param oth The RSA other primes information, {@code null} or
         *            empty list if not specified.
         * @return This builder.
         */
        public Builder otherPrimes(List<OtherPrimesInfo> oth) {

            this.oth = oth;
            return this;
        }


        /**
         * Sets the private RSA key, using the second representation
         * (see RFC 3447, section 3.2).
         *
         * @param priv The private RSA key, used to obtain the private
         *             exponent ({@code d}), the first prime factor
         *             ({@code p}), the second prime factor
         *             ({@code q}), the first factor CRT exponent
         *             ({@code dp}), the second factor CRT exponent
         *             ({@code dq}) and the first CRT coefficient
         *             ({@code qi}). Must not be {@code null}.
         * @return This builder.
         */
        public Builder privateKey(RSAPrivateCrtKey priv) {

            d = Base64URLValue.encode(priv.getPrivateExponent());
            p = Base64URLValue.encode(priv.getPrimeP());
            q = Base64URLValue.encode(priv.getPrimeQ());
            dp = Base64URLValue.encode(priv.getPrimeExponentP());
            dq = Base64URLValue.encode(priv.getPrimeExponentQ());
            qi = Base64URLValue.encode(priv.getCrtCoefficient());

            return this;
        }


        /**
         * Sets the private RSA key, using the second representation,
         * with optional other primes info (see RFC 3447, section 3.2).
         *
         * @param priv The private RSA key, used to obtain the private
         *             exponent ({@code d}), the first prime factor
         *             ({@code p}), the second prime factor
         *             ({@code q}), the first factor CRT exponent
         *             ({@code dp}), the second factor CRT exponent
         *             ({@code dq}), the first CRT coefficient
         *             ({@code qi}) and the other primes info
         *             ({@code oth}). Must not be {@code null}.
         * @return This builder.
         */
        public Builder privateKey(RSAMultiPrimePrivateCrtKey priv) {

            d = Base64URLValue.encode(priv.getPrivateExponent());
            p = Base64URLValue.encode(priv.getPrimeP());
            q = Base64URLValue.encode(priv.getPrimeQ());
            dp = Base64URLValue.encode(priv.getPrimeExponentP());
            dq = Base64URLValue.encode(priv.getPrimeExponentQ());
            qi = Base64URLValue.encode(priv.getCrtCoefficient());
            oth = OtherPrimesInfo.toList(priv.getOtherPrimeInfo());

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
         * Sets the operations ({@code key_ops}) of the JWK (for a
         * non-public key).
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
            requiredParams.put("e", e.toString());
            requiredParams.put("kty", KeyType.RSA.getValue());
            requiredParams.put("n", n.toString());
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

            this.keystore = keyStore;
            return this;
        }


        /**
         * Builds a new RSA JWK.
         *
         * @return The RSA JWK.
         * @throws IllegalStateException If the JWK parameters were
         *                               inconsistently specified.
         */
        public RSAKey build() {

            try {
                // The full constructor
                return new RSAKey(n, e, d, p, q, dp, dq, qi, oth,
                        priv,
                        use, ops, alg, kid, x5u, x5t256, x5c,
                        keystore);

            } catch (IllegalArgumentException e) {

                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }


    // Public RSA params

    /**
     * The modulus value of the RSA key.
     */
    private final Base64URLValue n;


    /**
     * The public exponent of the RSA key.
     */
    private final Base64URLValue e;


    // Private RSA params, 1st representation

    /**
     * The private exponent of the RSA key.
     */
    private final Base64URLValue d;


    // Private RSA params, 2nd representation

    /**
     * The first prime factor of the private RSA key.
     */
    private final Base64URLValue p;


    /**
     * The second prime factor of the private RSA key.
     */
    private final Base64URLValue q;


    /**
     * The first factor Chinese Remainder Theorem exponent of the private
     * RSA key.
     */
    private final Base64URLValue dp;


    /**
     * The second factor Chinese Remainder Theorem exponent of the private
     * RSA key.
     */
    private final Base64URLValue dq;


    /**
     * The first Chinese Remainder Theorem coefficient of the private RSA
     * key.
     */
    private final Base64URLValue qi;


    /**
     * The other primes information of the private RSA key, should they
     * exist. When only two primes have been used (the normal case), this
     * parameter MUST be omitted. When three or more primes have been used,
     * the number of array elements MUST be the number of primes used minus
     * two.
     */
    private final List<OtherPrimesInfo> oth;


    // Private RSA PKCS#11 key handle

    /**
     * Private PKCS#11 key handle.
     */
    private final PrivateKey privateKey;


    /**
     * Creates a new public RSA JSON Web Key (JWK) with the specified
     * parameters.
     *
     * @param n      The the modulus value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param e      The exponent value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(Base64URLValue n, Base64URLValue e,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        // Call the full constructor, all private key parameters are null
        this(n, e, null, null, null, null, null, null, null, null, use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by its first
     * representation (see RFC 3447, section 3.2).
     *
     * @param n      The the modulus value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param e      The exponent value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param d      The private exponent. It is represented as the
     *               Base64URL encoding of the value's big endian
     *               representation. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(Base64URLValue n, Base64URLValue e, Base64URLValue d,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        // Call the full constructor, the second private representation
        // parameters are all null
        this(n, e, d, null, null, null, null, null, null, null, use, ops, alg, kid,
                x5u, x5t256, x5c, ks);

        if (d == null) {
            throw new IllegalArgumentException("The private exponent must not be null");
        }
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by its
     * second representation (see RFC 3447, section 3.2).
     *
     * @param n      The the modulus value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param e      The exponent value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param p      The first prime factor. It is represented as the
     *               Base64URL encoding of the value's big endian
     *               representation. Must not be {@code null}.
     * @param q      The second prime factor. It is represented as the
     *               Base64URL encoding of the value's big endian
     *               representation. Must not be {@code null}.
     * @param dp     The first factor Chinese Remainder Theorem exponent.
     *               It is represented as the Base64URL encoding of the
     *               value's big endian representation. Must not be
     *               {@code null}.
     * @param dq     The second factor Chinese Remainder Theorem exponent.
     *               It is represented as the Base64URL encoding of the
     *               value's big endian representation. Must not be
     *               {@code null}.
     * @param qi     The first Chinese Remainder Theorem coefficient. It is
     *               represented as the Base64URL encoding of the value's
     *               big endian representation. Must not be {@code null}.
     * @param oth    The other primes information, should they exist,
     *               {@code null} or an empty list if not specified.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(Base64URLValue n, Base64URLValue e,
                  Base64URLValue p, Base64URLValue q,
                  Base64URLValue dp, Base64URLValue dq, Base64URLValue qi,
                  List<OtherPrimesInfo> oth,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        // Call the full constructor, the first private representation
        // d param is null
        this(n, e, null, p, q, dp, dq, qi, oth, null, use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);

        if (p == null) {
            throw new IllegalArgumentException("The first prime factor must not be null");
        }

        if (q == null) {
            throw new IllegalArgumentException("The second prime factor must not be null");
        }

        if (dp == null) {
            throw new IllegalArgumentException("The first factor CRT exponent must not be null");
        }

        if (dq == null) {
            throw new IllegalArgumentException("The second factor CRT exponent must not be null");
        }

        if (qi == null) {
            throw new IllegalArgumentException("The first CRT coefficient must not be null");
        }
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key can be specified by its
     * first representation, its second representation (see RFC 3447,
     * section 3.2), or by a PKCS#11 handle as {@link PrivateKey}.
     *
     * <p>A valid first private RSA key representation must specify the
     * {@code d} parameter.
     *
     * <p>A valid second private RSA key representation must specify all
     * required Chinese Remainder Theorem (CRT) parameters - {@code p},
     * {@code q}, {@code dp}, {@code dq} and {@code qi}, else an
     * {@link java.lang.IllegalArgumentException} will be thrown.
     *
     * @param n      The the modulus value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param e      The exponent value for the public RSA key. It is
     *               represented as the Base64URL encoding of value's big
     *               endian representation. Must not be {@code null}.
     * @param d      The private exponent. It is represented as the Base64URL
     *               encoding of the value's big endian representation. May
     *               be {@code null}.
     * @param p      The first prime factor. It is represented as the
     *               Base64URL encoding of the value's big endian
     *               representation. May be {@code null}.
     * @param q      The second prime factor. It is represented as the
     *               Base64URL encoding of the value's big endian
     *               representation. May be {@code null}.
     * @param dp     The first factor Chinese Remainder Theorem exponent. It
     *               is represented as the Base64URL encoding of the value's
     *               big endian representation. May be {@code null}.
     * @param dq     The second factor Chinese Remainder Theorem exponent. It
     *               is represented as the Base64URL encoding of the value's
     *               big endian representation. May be {@code null}.
     * @param qi     The first Chinese Remainder Theorem coefficient. It is
     *               represented as the Base64URL encoding of the value's big
     *               endian representation. May be {@code null}.
     * @param oth    The other primes information, should they exist,
     *               {@code null} or an empty list if not specified.
     * @param use    The key use, {@code null} if not specified or if the key
     *               is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null} if
     *               not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(Base64URLValue n, Base64URLValue e,
                  Base64URLValue d,
                  Base64URLValue p, Base64URLValue q,
                  Base64URLValue dp, Base64URLValue dq, Base64URLValue qi,
                  List<OtherPrimesInfo> oth,
                  PrivateKey privateKey,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        super(KeyType.RSA, use, ops, alg, kid, x5u, x5t256, x5c, ks);


        // Ensure the public params are defined

        if (n == null) {
            throw new IllegalArgumentException("The modulus value must not be null");
        }
        this.n = n;


        if (e == null) {
            throw new IllegalArgumentException("The public exponent value must not be null");
        }
        this.e = e;

        if (getParsedX509CertChain() != null) {
            if (!matches(getParsedX509CertChain().get(0))) {
                throw new IllegalArgumentException("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
            }
        }

        // Private params, 1st representation

        this.d = d;


        // Private params, 2nd representation, check for consistency

        if (p != null && q != null && dp != null && dq != null && qi != null) {

            // CRT params fully specified
            this.p = p;
            this.q = q;
            this.dp = dp;
            this.dq = dq;
            this.qi = qi;

            // Other RSA primes info optional, default to empty list
            if (oth != null) {
                this.oth = Collections.unmodifiableList(oth);
            } else {
                this.oth = Collections.emptyList();
            }

        } else if (p == null && q == null && dp == null && dq == null && qi == null && oth == null) {

            // No CRT params
            this.p = null;
            this.q = null;
            this.dp = null;
            this.dq = null;
            this.qi = null;

            this.oth = Collections.emptyList();

        } else if (p != null || q != null || dp != null || dq != null || qi != null) {

            if (p == null) {
                throw new IllegalArgumentException("Incomplete second private (CRT) representation: The first prime factor must not be null");
            } else if (q == null) {
                throw new IllegalArgumentException("Incomplete second private (CRT) representation: The second prime factor must not be null");
            } else if (dp == null) {
                throw new IllegalArgumentException("Incomplete second private (CRT) representation: The first factor CRT exponent must not be null");
            } else if (dq == null) {
                throw new IllegalArgumentException("Incomplete second private (CRT) representation: The second factor CRT exponent must not be null");
            } else {
                throw new IllegalArgumentException("Incomplete second private (CRT) representation: The first CRT coefficient must not be null");
            }
        } else {
            // No CRT params
            this.p = null;
            this.q = null;
            this.dp = null;
            this.dq = null;
            this.qi = null;
            this.oth = Collections.emptyList();
        }

        this.privateKey = privateKey; // PKCS#11 handle
    }


    /**
     * Creates a new public RSA JSON Web Key (JWK) with the specified
     * parameters.
     *
     * @param pub    The public RSA key to represent. Must not be
     *               {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(RSAPublicKey pub,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        this(Base64URLValue.encode(pub.getModulus()),
                Base64URLValue.encode(pub.getPublicExponent()),
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by its first
     * representation (see RFC 3447, section 3.2).
     *
     * @param pub    The public RSA key to represent. Must not be
     *               {@code null}.
     * @param priv   The private RSA key to represent. Must not be
     *               {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(RSAPublicKey pub, RSAPrivateKey priv,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        this(Base64URLValue.encode(pub.getModulus()),
                Base64URLValue.encode(pub.getPublicExponent()),
                Base64URLValue.encode(priv.getPrivateExponent()),
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by its second
     * representation (see RFC 3447, section 3.2).
     *
     * @param pub    The public RSA key to represent. Must not be
     *               {@code null}.
     * @param priv   The private RSA key to represent. Must not be
     *               {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(RSAPublicKey pub, RSAPrivateCrtKey priv,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        this(Base64URLValue.encode(pub.getModulus()),
                Base64URLValue.encode(pub.getPublicExponent()),
                Base64URLValue.encode(priv.getPrivateExponent()),
                Base64URLValue.encode(priv.getPrimeP()),
                Base64URLValue.encode(priv.getPrimeQ()),
                Base64URLValue.encode(priv.getPrimeExponentP()),
                Base64URLValue.encode(priv.getPrimeExponentQ()),
                Base64URLValue.encode(priv.getCrtCoefficient()),
                null,
                null,
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by its second
     * representation, with optional other primes info (see RFC 3447,
     * section 3.2).
     *
     * @param pub    The public RSA key to represent. Must not be
     *               {@code null}.
     * @param priv   The private RSA key to represent. Must not be
     *               {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(RSAPublicKey pub, RSAMultiPrimePrivateCrtKey priv,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        this(Base64URLValue.encode(pub.getModulus()),
                Base64URLValue.encode(pub.getPublicExponent()),
                Base64URLValue.encode(priv.getPrivateExponent()),
                Base64URLValue.encode(priv.getPrimeP()),
                Base64URLValue.encode(priv.getPrimeQ()),
                Base64URLValue.encode(priv.getPrimeExponentP()),
                Base64URLValue.encode(priv.getPrimeExponentQ()),
                Base64URLValue.encode(priv.getCrtCoefficient()),
                OtherPrimesInfo.toList(priv.getOtherPrimeInfo()),
                null,
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }


    /**
     * Creates a new public / private RSA JSON Web Key (JWK) with the
     * specified parameters. The private RSA key is specified by a PKCS#11
     * handle.
     *
     * @param pub    The public RSA key to represent. Must not be
     *               {@code null}.
     * @param priv   The private RSA key as PKCS#11 handle, {@code null} if
     *               not specified.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID. {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    public RSAKey(RSAPublicKey pub, PrivateKey priv,
                  KeyUse use, Set<KeyOperation> ops, Algorithm alg, String kid,
                  URI x5u, Base64URLValue x5t256, List<Base64Value> x5c,
                  KeyStore ks) {

        this(Base64URLValue.encode(pub.getModulus()),
                Base64URLValue.encode(pub.getPublicExponent()),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                priv,
                use, ops, alg, kid,
                x5u, x5t256, x5c,
                ks);
    }

    /**
     * Gets the modulus value ({@code n}) of the RSA key.
     *
     * @return The RSA key modulus. It is represented as the Base64URL
     * encoding of the value's big endian representation.
     */
    public Base64URLValue getModulus() {

        return n;
    }


    /**
     * Gets the public exponent ({@code e}) of the RSA key.
     *
     * @return The public RSA key exponent. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     */
    public Base64URLValue getPublicExponent() {

        return e;
    }


    /**
     * Gets the private exponent ({@code d}) of the RSA key.
     *
     * @return The private RSA key exponent. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the second representation only).
     */
    public Base64URLValue getPrivateExponent() {

        return d;
    }


    /**
     * Gets the first prime factor ({@code p}) of the private RSA key.
     *
     * @return The RSA first prime factor. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the first representation only).
     */
    public Base64URLValue getFirstPrimeFactor() {

        return p;
    }


    /**
     * Gets the second prime factor ({@code q}) of the private RSA key.
     *
     * @return The RSA second prime factor. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the first representation only).
     */
    public Base64URLValue getSecondPrimeFactor() {

        return q;
    }


    /**
     * Gets the first factor Chinese Remainder Theorem (CRT) exponent
     * ({@code dp}) of the private RSA key.
     *
     * @return The RSA first factor CRT exponent. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the first representation only).
     */
    public Base64URLValue getFirstFactorCRTExponent() {

        return dp;
    }


    /**
     * Gets the second factor Chinese Remainder Theorem (CRT) exponent
     * ({@code dq}) of the private RSA key.
     *
     * @return The RSA second factor CRT exponent. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the first representation only).
     */
    public Base64URLValue getSecondFactorCRTExponent() {

        return dq;
    }


    /**
     * Gets the first Chinese Remainder Theorem (CRT) coefficient
     * ({@code qi})} of the private RSA key.
     *
     * @return The RSA first CRT coefficient. It is represented as the
     * Base64URL encoding of the value's big endian representation.
     * {@code null} if not specified (for a public key or a private
     * key using the first representation only).
     */
    public Base64URLValue getFirstCRTCoefficient() {

        return qi;
    }


    /**
     * Gets the other primes information ({@code oth}) for the private RSA
     * key, should they exist.
     *
     * @return The RSA other primes information, {@code null} or empty list
     * if not specified.
     */
    public List<OtherPrimesInfo> getOtherPrimes() {

        return oth;
    }


    /**
     * Returns a standard {@code java.security.interfaces.RSAPublicKey}
     * representation of this RSA JWK.
     *
     * @return The public RSA key.
     */
    public RSAPublicKey toRSAPublicKey() {

        BigInteger modulus = n.decodeToBigInteger();
        BigInteger exponent = e.decodeToBigInteger();

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");

            return (RSAPublicKey) factory.generatePublic(spec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

            throw new InvalidKeyException(e.getMessage(), e);
        }
    }


    /**
     * Returns a standard {@code java.security.interfaces.RSAPrivateKey}
     * representation of this RSA JWK.
     *
     * @return The private RSA key, {@code null} if not specified by this
     * JWK.
     */
    public RSAPrivateKey toRSAPrivateKey() {

        if (d == null) {
            // no private key
            return null;
        }

        BigInteger modulus = n.decodeToBigInteger();
        BigInteger privateExponent = d.decodeToBigInteger();

        RSAPrivateKeySpec spec;

        if (p == null) {
            // Use 1st representation
            spec = new RSAPrivateKeySpec(modulus, privateExponent);

        } else {
            // Use 2nd (CRT) representation
            BigInteger publicExponent = e.decodeToBigInteger();
            BigInteger primeP = p.decodeToBigInteger();
            BigInteger primeQ = q.decodeToBigInteger();
            BigInteger primeExponentP = dp.decodeToBigInteger();
            BigInteger primeExponentQ = dq.decodeToBigInteger();
            BigInteger crtCoefficient = qi.decodeToBigInteger();

            if (oth != null && !oth.isEmpty()) {
                // Construct other info spec
                RSAOtherPrimeInfo[] otherInfo = new RSAOtherPrimeInfo[oth.size()];

                for (int i = 0; i < oth.size(); i++) {

                    OtherPrimesInfo opi = oth.get(i);

                    BigInteger otherPrime = opi.getPrimeFactor().decodeToBigInteger();
                    BigInteger otherPrimeExponent = opi.getFactorCRTExponent().decodeToBigInteger();
                    BigInteger otherCrtCoefficient = opi.getFactorCRTCoefficient().decodeToBigInteger();

                    otherInfo[i] = new RSAOtherPrimeInfo(otherPrime,
                            otherPrimeExponent,
                            otherCrtCoefficient);
                }

                spec = new RSAMultiPrimePrivateCrtKeySpec(modulus,
                        publicExponent,
                        privateExponent,
                        primeP,
                        primeQ,
                        primeExponentP,
                        primeExponentQ,
                        crtCoefficient,
                        otherInfo);
            } else {
                // Construct spec with no other info
                spec = new RSAPrivateCrtKeySpec(modulus,
                        publicExponent,
                        privateExponent,
                        primeP,
                        primeQ,
                        primeExponentP,
                        primeExponentQ,
                        crtCoefficient);
            }
        }

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");

            return (RSAPrivateKey) factory.generatePrivate(spec);

        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {

            throw new InvalidKeyException(e.getMessage(), e);
        }
    }


    @Override
    public PublicKey toPublicKey() {

        return toRSAPublicKey();
    }


    @Override
    public PrivateKey toPrivateKey() {

        PrivateKey prv = toRSAPrivateKey();

        if (prv != null) {
            // Return private RSA key with key material
            return prv;
        }

        // Return private RSA key as PKCS#11 handle, or null
        return privateKey;
    }


    /**
     * Returns a standard {@code java.security.KeyPair} representation of
     * this RSA JWK.
     *
     * @return The RSA key pair. The private RSA key will be {@code null}
     * if not specified.
     */
    @Override
    public KeyPair toKeyPair() {

        return new KeyPair(toRSAPublicKey(), toPrivateKey());
    }


    @Override
    public boolean matches(X509Certificate cert) {

        RSAPublicKey certRSAKey;
        try {
            certRSAKey = (RSAPublicKey) getParsedX509CertChain().get(0).getPublicKey();
        } catch (ClassCastException ex) {
            return false;
        }
        if (!e.decodeToBigInteger().equals(certRSAKey.getPublicExponent())) {
            return false;
        }
        return n.decodeToBigInteger().equals(certRSAKey.getModulus());
    }


    @Override
    public LinkedHashMap<String, String> getRequiredParams() {

        // Put mandatory params in sorted order
        LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
        requiredParams.put("e", e.toString());
        requiredParams.put("kty", getKeyType().getValue());
        requiredParams.put("n", n.toString());
        return requiredParams;
    }


    @Override
    public boolean isPrivate() {

        // Check if 1st or 2nd form params are specified, or PKCS#11 handle
        return d != null || p != null || privateKey != null;
    }


    @Override
    public int size() {

        try {
            return ByteUtils.safeBitLength(n.decode());
        } catch (IntegerOverflowException e) {
            throw new ArithmeticException(e.getMessage());
        }
    }


    /**
     * Returns a copy of this RSA JWK with any private values removed.
     *
     * @return The copied public RSA JWK.
     */
    @Override
    public RSAKey toPublicJWK() {

        return new RSAKey(
                getModulus(), getPublicExponent(),
                getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
                getX509CertURL(), getX509CertSHA256Thumbprint(), getX509CertChain(),
                getKeyStore());
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = super.toJSONObject();

        // Append public RSA key specific attributes
        result.add("n", n.toString());
        result.add("e", e.toString());
        if (d != null) {
            result.add("d", d.toString());
        }
        if (p != null) {
            result.add("p", p.toString());
        }
        if (q != null) {
            result.add("q", q.toString());
        }
        if (dp != null) {
            result.add("dp", dp.toString());
        }
        if (dq != null) {
            result.add("dq", dq.toString());
        }
        if (qi != null) {
            result.add("qi", qi.toString());
        }
        if (oth != null && !oth.isEmpty()) {

            JsonArrayBuilder otherArray = Json.createArrayBuilder();

            for (OtherPrimesInfo other : oth) {

                JsonObjectBuilder otherObject = Json.createObjectBuilder()
                        .add("r", other.r.toString())
                        .add("d", other.d.toString())
                        .add("t", other.t.toString());

                otherArray.add(otherObject);
            }

            result.add("oth", otherArray);
        }

        return result;
    }


    /**
     * Parses a public / private RSA JWK from the specified JSON object
     * string representation.
     *
     * @param value The JSON object string to parse. Must not be {@code null}.
     * @return The public / private RSA JWK.
     * @throws ParseException If the string couldn't be parsed to an RSA
     *                        JWK.
     */
    public static RSAKey parse(String value)
            throws ParseException {

        return parse(JSONObjectUtils.parse(value));
    }


    /**
     * Parses a public / private RSA JWK from the specified JSON object
     * representation.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The public / private RSA Key.
     * @throws ParseException If the JSON object couldn't be parsed to an
     *                        RSA JWK.
     */
    public static RSAKey parse(JsonObject jsonObject)
            throws ParseException {

        // Parse the mandatory public key parameters first
        Base64URLValue n = new Base64URLValue(jsonObject.getString("n"));
        Base64URLValue e = new Base64URLValue(jsonObject.getString("e"));

        // Check key type
        KeyType kty = KeyType.parse(jsonObject.getString("kty"));
        if (kty != KeyType.RSA) {
            throw new ParseException("The key type \"kty\" must be RSA", 0);
        }

        // Parse the optional private key parameters

        // 1st private representation
        Base64URLValue d = null;
        if (jsonObject.containsKey("d")) {
            d = new Base64URLValue(jsonObject.getString("d"));
        }

        // 2nd private (CRT) representation
        Base64URLValue p = null;
        if (jsonObject.containsKey("p")) {
            p = new Base64URLValue(jsonObject.getString("p"));
        }
        Base64URLValue q = null;
        if (jsonObject.containsKey("q")) {
            q = new Base64URLValue(jsonObject.getString("q"));
        }
        Base64URLValue dp = null;
        if (jsonObject.containsKey("dp")) {
            dp = new Base64URLValue(jsonObject.getString("dp"));
        }
        Base64URLValue dq = null;
        if (jsonObject.containsKey("dq")) {
            dq = new Base64URLValue(jsonObject.getString("dq"));
        }
        Base64URLValue qi = null;
        if (jsonObject.containsKey("qi")) {
            qi = new Base64URLValue(jsonObject.getString("qi"));
        }

        List<OtherPrimesInfo> oth = null;
        if (jsonObject.containsKey("oth")) {

            JsonArray arr = jsonObject.getJsonArray("oth");
            oth = new ArrayList<>(arr.size());

            for (Object o : arr) {

                if (o instanceof JsonObject) {
                    JsonObject otherJson = (JsonObject) o;

                    Base64URLValue r = new Base64URLValue(otherJson.getString("r"));
                    Base64URLValue odq = new Base64URLValue(otherJson.getString("dq"));
                    Base64URLValue t = new Base64URLValue(otherJson.getString("t"));

                    OtherPrimesInfo prime = new OtherPrimesInfo(r, odq, t);
                    oth.add(prime);
                }
            }
        }

        try {
            return new RSAKey(n, e, d, p, q, dp, dq, qi, oth, null,
                    JWKMetadata.parseKeyUse(jsonObject),
                    JWKMetadata.parseKeyOperations(jsonObject),
                    JWKMetadata.parseAlgorithm(jsonObject),
                    JWKMetadata.parseKeyID(jsonObject),
                    JWKMetadata.parseX509CertURL(jsonObject),
                    JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                    JWKMetadata.parseX509CertChain(jsonObject),
                    null);

        } catch (IllegalArgumentException ex) {
            // Inconsistent 2nd spec, conflicting 'use' and 'key_ops', etc.
            throw new ParseException(ex.getMessage(), 0);
        }
    }


    /**
     * Parses a public RSA JWK from the specified X.509 certificate.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * <p>Sets the following JWK parameters:
     *
     * <ul>
     *     <li>The JWK use inferred by {@link KeyUse#from}.
     *     <li>The JWK ID from the X.509 serial number (in base 10).
     *     <li>The JWK X.509 certificate chain (this certificate only).
     *     <li>The JWK X.509 certificate SHA-256 thumbprint.
     * </ul>
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return The public RSA key.
     */
    public static RSAKey parse(X509Certificate cert) {

        if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
            throw new JOSEException("The public key of the X.509 certificate is not RSA");
        }

        RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            return new RSAKey.Builder(publicKey)
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
     * Loads a public / private RSA JWK from the specified JCA key store.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * @param keyStore The key store. Must not be {@code null}.
     * @param alias    The alias. Must not be {@code null}.
     * @param pin      The pin to unlock the private key if any, empty or
     *                 {@code null} if not required.
     * @return The public / private RSA key, {@code null} if no key with
     * the specified alias was found.
     * @throws KeyStoreException On a key store exception.
     */
    public static RSAKey load(KeyStore keyStore,
                              String alias,
                              char[] pin)
            throws KeyStoreException {

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);

        if (!(cert instanceof X509Certificate)) {
            return null;
        }

        X509Certificate x509Cert = (X509Certificate) cert;

        if (!(x509Cert.getPublicKey() instanceof RSAPublicKey)) {
            throw new JOSEException("Couldn't load RSA JWK: The key algorithm is not RSA");
        }

        RSAKey rsaJWK = RSAKey.parse(x509Cert);

        // Let kid=alias
        rsaJWK = new RSAKey.Builder(rsaJWK).keyID(alias).keyStore(keyStore).build();

        // Check for private counterpart
        Key key;
        try {
            key = keyStore.getKey(alias, pin);
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't retrieve private RSA key (bad pin?): " + e.getMessage(), e);
        }

        if (key instanceof RSAPrivateKey) {
            // Simple file based key store
            return new RSAKey.Builder(rsaJWK)
                    .privateKey((RSAPrivateKey) key)
                    .build();
        } else if (key instanceof PrivateKey && "RSA".equalsIgnoreCase(key.getAlgorithm())) {
            // PKCS#11 store
            return new RSAKey.Builder(rsaJWK)
                    .privateKey((PrivateKey) key)
                    .build();
        } else {
            return rsaJWK;
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RSAKey)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        RSAKey rsaKey = (RSAKey) o;
        return Objects.equals(n, rsaKey.n) &&
                Objects.equals(e, rsaKey.e) &&
                Objects.equals(d, rsaKey.d) &&
                Objects.equals(p, rsaKey.p) &&
                Objects.equals(q, rsaKey.q) &&
                Objects.equals(dp, rsaKey.dp) &&
                Objects.equals(dq, rsaKey.dq) &&
                Objects.equals(qi, rsaKey.qi) &&
                Objects.equals(oth, rsaKey.oth) &&
                Objects.equals(privateKey, rsaKey.privateKey);
    }


    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), n, e, d, p, q, dp, dq, qi, oth, privateKey);
    }
}
