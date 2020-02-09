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
import be.atbash.ee.security.octopus.nimbus.jose.AlgorithmFamily;

/**
 * JSON Web Encryption (JWE) algorithm name, represents the {@code alg} header
 * parameter in JWE objects. This class is immutable.
 *
 * <p>Includes constants for the following standard JWE algorithm names:
 *
 * <ul>
 *     <li>{@link #RSA_OAEP_256 RSA-OAEP-256}
 *     <li>{@link #A128KW}
 *     <li>{@link #A192KW}
 *     <li>{@link #A256KW}
 *     <li>{@link #DIR dir}
 *     <li>{@link #ECDH_ES ECDH-ES}
 *     <li>{@link #ECDH_ES_A128KW ESDH-ES+A128KW}
 *     <li>{@link #ECDH_ES_A128KW ESDH-ES+A192KW}
 *     <li>{@link #ECDH_ES_A256KW ESDH-ES+A256KW}
 *     <li>{@link #PBES2_HS256_A128KW PBES2-HS256+A128KW}
 *     <li>{@link #PBES2_HS384_A192KW PBES2-HS256+A192KW}
 *     <li>{@link #PBES2_HS512_A256KW PBES2-HS256+A256KW}
 * </ul>
 *
 * <p>Additional JWE algorithm names can be defined using the constructors.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class JWEAlgorithm extends Algorithm {


    private static final long serialVersionUID = 1L;

    /**
     * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
     * with the SHA-256 hash function and the MGF1 with SHA-256 mask
     * generation function.
     */
    public static final JWEAlgorithm RSA_OAEP_256 = new JWEAlgorithm("RSA-OAEP-256");


    /**
     * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
     * using 128 bit keys.
     */
    public static final JWEAlgorithm A128KW = new JWEAlgorithm("A128KW");


    /**
     * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
     * using 192 bit keys.
     */
    public static final JWEAlgorithm A192KW = new JWEAlgorithm("A192KW");


    /**
     * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
     * using 256 bit keys.
     */
    public static final JWEAlgorithm A256KW = new JWEAlgorithm("A256KW");


    /**
     * Direct use of a shared symmetric key as the Content Encryption Key
     * (CEK) for the block encryption step (rather than using the symmetric
     * key to wrap the CEK).
     */
    public static final JWEAlgorithm DIR = new JWEAlgorithm("dir");


    /**
     * Elliptic Curve Diffie-Hellman Ephemeral Static (RFC 6090) key
     * agreement using the Concat KDF, as defined in section 5.8.1 of
     * NIST.800-56A, with the agreed-upon key being used directly as the
     * Content Encryption Key (CEK) (rather than being used to wrap the
     * CEK).
     */
    public static final JWEAlgorithm ECDH_ES = new JWEAlgorithm("ECDH-ES");


    /**
     * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
     * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
     * Encryption Key (CEK) with the "A128KW" function (rather than being
     * used directly as the CEK).
     */
    public static final JWEAlgorithm ECDH_ES_A128KW = new JWEAlgorithm("ECDH-ES+A128KW");


    /**
     * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
     * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
     * Encryption Key (CEK) with the "A192KW" function (rather than being
     * used directly as the CEK).
     */
    public static final JWEAlgorithm ECDH_ES_A192KW = new JWEAlgorithm("ECDH-ES+A192KW");


    /**
     * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
     * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
     * Encryption Key (CEK) with the "A256KW" function (rather than being
     * used directly as the CEK).
     */
    public static final JWEAlgorithm ECDH_ES_A256KW = new JWEAlgorithm("ECDH-ES+A256KW");


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 128 bit keys.
     */
    public static final JWEAlgorithm A128GCMKW = new JWEAlgorithm("A128GCMKW");


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 192 bit keys.
     */
    public static final JWEAlgorithm A192GCMKW = new JWEAlgorithm("A192GCMKW");


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 256 bit keys.
     */
    public static final JWEAlgorithm A256GCMKW = new JWEAlgorithm("A256GCMKW");


    /**
     * PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
     * (RFC 3394) using 128 bit keys for the encryption scheme.
     */
    public static final JWEAlgorithm PBES2_HS256_A128KW = new JWEAlgorithm("PBES2-HS256+A128KW");


    /**
     * PBES2 (RFC 2898) with HMAC SHA-384 as the PRF and AES Key Wrap
     * (RFC 3394) using 192 bit keys for the encryption scheme.
     */
    public static final JWEAlgorithm PBES2_HS384_A192KW = new JWEAlgorithm("PBES2-HS384+A192KW");


    /**
     * PBES2 (RFC 2898) with HMAC SHA-512 as the PRF and AES Key Wrap
     * (RFC 3394) using 256 bit keys for the encryption scheme.
     */
    public static final JWEAlgorithm PBES2_HS512_A256KW = new JWEAlgorithm("PBES2-HS512+A256KW");


    /**
     * JWE algorithm family.
     */
    public static final class Family extends AlgorithmFamily<JWEAlgorithm> {


        private static final long serialVersionUID = 1L;


        /**
         * RSA key encryption.
         */
        public static final Family RSA = new Family(RSA_OAEP_256);


        /**
         * AES key wrap.
         */
        public static final Family AES_KW = new Family(A128KW, A192KW, A256KW);


        /**
         * Elliptic Curve Diffie-Hellman Ephemeral Static key
         * agreement.
         */
        public static final Family ECDH_ES = new Family(JWEAlgorithm.ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW);


        /**
         * AES GCM key wrap.
         */
        // FIXME Verify how we can use it (or if it is possible) in JWEEncoder.
        public static final Family AES_GCM_KW = new Family(A128GCMKW, A192GCMKW, A256GCMKW);


        /*
         * Password-Based Cryptography Specification Version 2.0
         */
        public static final Family PBES2 = new Family(PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW);

        /***
         * Creates a new JWE algorithm family.
         *
         * @param algs The JWE algorithms of the family. Must not be
         *             {@code null}.
         */
        public Family(JWEAlgorithm... algs) {
            super(algs);
        }
    }


    /**
     * Creates a new JSON Web Encryption (JWE) algorithm.
     *
     * @param name The algorithm name. Must not be {@code null}.
     */
    public JWEAlgorithm(String name) {

        super(name);
    }

    /**
     * Parses a JWE algorithm from the specified string.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The JWE algorithm (matching standard algorithm constant, else
     * a newly created algorithm).
     */
    public static JWEAlgorithm parse(String value) {

        if (value.equals(RSA_OAEP_256.getName())) {
            return RSA_OAEP_256;
        } else if (value.equals(A128KW.getName())) {
            return A128KW;
        } else if (value.equals(A192KW.getName())) {
            return A192KW;
        } else if (value.equals(A256KW.getName())) {
            return A256KW;
        } else if (value.equals(DIR.getName())) {
            return DIR;
        } else if (value.equals(ECDH_ES.getName())) {
            return ECDH_ES;
        } else if (value.equals(ECDH_ES_A128KW.getName())) {
            return ECDH_ES_A128KW;
        } else if (value.equals(ECDH_ES_A192KW.getName())) {
            return ECDH_ES_A192KW;
        } else if (value.equals(ECDH_ES_A256KW.getName())) {
            return ECDH_ES_A256KW;
        } else if (value.equals(A128GCMKW.getName())) {
            return A128GCMKW;
        } else if (value.equals(A192GCMKW.getName())) {
            return A192GCMKW;
        } else if (value.equals(A256GCMKW.getName())) {
            return A256GCMKW;
        } else if (value.equals(PBES2_HS256_A128KW.getName())) {
            return PBES2_HS256_A128KW;
        } else if (value.equals(PBES2_HS384_A192KW.getName())) {
            return PBES2_HS384_A192KW;
        } else if (value.equals(PBES2_HS512_A256KW.getName())) {
            return PBES2_HS512_A256KW;
        } else {
            return new JWEAlgorithm(value);
        }
    }
}
