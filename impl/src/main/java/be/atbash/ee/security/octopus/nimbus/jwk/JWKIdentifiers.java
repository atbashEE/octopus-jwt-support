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

import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.util.PublicAPI;

/**
 * JSON Web Key (JWK) parameter names. The JWK parameter names defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a> (JWK),
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518</a> (JWA)
 * and other JOSE related standards are tracked in a
 * <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters">JWK
 * parameters registry</a> administered by IANA.
 *
 * @author Nathaniel Hart
 * @version 2021-07-02
 */
@PublicAPI
public final class JWKIdentifiers {

    private JWKIdentifiers() {
    }

    ////////////////////////////////////////////////////////////////////////////////
    // RFC 7517 JSON Web Key (JWK) Parameters
    ////////////////////////////////////////////////////////////////////////////////


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.1">RFC 7517 "kty" (Key Type) Parameter</a>
     */
    public static final String KEY_TYPE = "kty";


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">RFC 7517 "use" (Public Key Use) Parameter</a>
     */
    public static final String PUBLIC_KEY_USE = "use";


    /**
     * Use with {@link KeyType#OKP}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">RFC 7517 "enc" (encryption) Parameter Value</a>
     */
    public static final String ENCRYPTION_ALGORITHM = HeaderParameterNames.ENCRYPTION_ALGORITHM;


    /**
     * Use with {@link KeyType#OKP}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">RFC 7517 "sig" (signature) Parameter Value</a>
     */
    public static final String SIGNATURE = "sig";


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">RFC 7517 "key_ops" (Key Operations) Parameter</a>
     */
    public static final String KEY_OPS = "key_ops";


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.4">RFC 7517 "alg" (Algorithm) Parameter</a>
     */
    public static final String ALGORITHM = HeaderParameterNames.ALGORITHM;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">RFC 7517 "kid" (Key ID) Parameter</a>
     */
    public static final String KEY_ID = HeaderParameterNames.KEY_ID;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.6">RFC 7517 "x5u" (X.509 URL) Parameter</a>
     */
    public static final String X_509_URL = HeaderParameterNames.X_509_URL;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.7">RFC 7517 "x5c" (X.509 Certificate Chain) Parameter</a>
     */
    public static final String X_509_CERT_CHAIN = HeaderParameterNames.X_509_CERT_CHAIN;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.8">RFC 7517 "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter</a>
     */
    public static final String X_509_CERT_SHA_1_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.9">RFC 7517 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
     * Parameter</a>
     */
    public static final String X_509_CERT_SHA_256_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT;


    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5.1">RFC 7517 "keys" Parameter</a>
     */
    public static final String KEYS = "keys";


    /**
     * The Key Type Parameter for {@link KeyType#EC}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-6.1">"kty" (Key Type) Parameter Values</a>
     */
    public static final String ELLIPTIC_CURVE_KEY_TYPE = "EC";


    /**
     * The Key Type Parameter for {@link KeyType#RSA}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-6.1">"kty" (Key Type) Parameter Values</a>
     */
    public static final String RSA_KEY_TYPE = "RSA";


    /**
     * The Key Type Parameter for {@link KeyType#OCT}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-6.1">"kty" (Key Type) Parameter Values</a>
     */
    public static final String OCTET_SEQUENCE_KEY_TYPE = "oct";


    ////////////////////////////////////////////////////////////////////////////////
    // RFC 7518 JSON Web Algorithms (JWA) Parameters
    ////////////////////////////////////////////////////////////////////////////////


    /**
     * Use with {@link KeyType#EC}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518 "crv" (Curve) Parameter</a>
     */
    public static final String CURVE = "crv";


    /**
     * Use with {@link KeyType#EC}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2">RFC 7518 "x" (X Coordinate) Parameter</a>
     */
    public static final String X_COORD = "x";


    /**
     * Use with {@link KeyType#EC}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3">RFC 7518 "y" (Y Coordinate) Parameter</a>
     */
    public static final String Y_COORD = "y";


    /**
     * An identifier shared by {@link #ECC_PRIVATE_KEY}, {@link #PRIVATE_EXPONENT}, and {@link #FACTOR_CRT_EXPONENT}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1">RFC 7518 "d" (ECC Private Key) Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1">RFC 7518 "d" (Private Exponent) Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.2">RFC 7518 "d" (Factor CRT Exponent)</a>
     */
    public static final String D = "d";


    /**
     * Use with {@link KeyType#EC}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1">RFC 7518 "d" (ECC Private Key) Parameter</a>
     */
    public static final String ECC_PRIVATE_KEY = D;


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1">RFC 7518 "n" (Modulus) Parameter</a>
     */
    public static final String MODULUS = "n";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2">RFC 7518 "e" (Exponent) Parameter</a>
     */
    public static final String EXPONENT = "e";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1">RFC 7518 "d" (Private Exponent) Parameter</a>
     */
    public static final String PRIVATE_EXPONENT = D;


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2">RFC 7518 "p" (First Prime Factor) Parameter</a>
     */
    public static final String FIRST_PRIME_FACTOR = "p";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.3">RFC 7518 "q" (Second Prime Factor) Parameter</a>
     */
    public static final String SECOND_PRIME_FACTOR = "q";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4">RFC 7518 "dp" (First Factor CRT Exponent) Parameter</a>
     */
    public static final String FIRST_FACTOR_CRT_EXPONENT = "dp";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5">RFC 7518 "dq" (Second Factor CRT Exponent) Parameter</a>
     */
    public static final String SECOND_FACTOR_CRT_EXPONENT = "dq";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6">RFC 7518 "qi" (First CRT Coefficient) Parameter</a>
     */
    public static final String FIRST_CRT_COEFFICIENT = "qi";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7">RFC 7518 "oth" (Other Primes Info) Parameter</a>
     */
    public static final String OTHER_PRIMES = "oth";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.1">RFC 7518 "r" (Prime Factor)</a>
     */
    public static final String PRIME_FACTOR = "r";


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.2">RFC 7518 "d" (Factor CRT Exponent)</a>
     */
    public static final String FACTOR_CRT_EXPONENT = D;


    /**
     * Use with {@link KeyType#RSA}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.3">RFC 7518 "t" (Factor CRT Coefficient)</a>
     */
    public static final String FACTOR_CRT_COEFFICIENT = "t";


    /**
     * Use with {@link KeyType#OCT}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1">RFC 7518 "k" (Key Value) Parameter</a>
     */
    public static final String OCT_KEY_VALUE = "k";


    ////////////////////////////////////////////////////////////////////////////////
    // RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE
    ////////////////////////////////////////////////////////////////////////////////


    /**
     * The Key Type Parameter for {@link KeyType#OKP}
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "OKP" (Octet Key Pair)</a>
     */
    public static final String OCTET_KEY_PAIR = "OKP";
}