/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
 * Encryption method name, represents the {@code enc} header parameter in JSON
 * Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes constants for the following standard encryption method names:
 *
 * <ul>
 *     <li>{@link #A128CBC_HS256 A128CBC-HS256}
 *     <li>{@link #A192CBC_HS384 A192CBC-HS384}
 *     <li>{@link #A256CBC_HS512 A256CBC-HS512}
 *     <li>{@link #A128GCM}
 *     <li>{@link #A192GCM}
 *     <li>{@link #A256GCM}
 * </ul>
 *
 * <p>Additional encryption method names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-10-14
 */
public final class EncryptionMethod extends Algorithm {


    private static final long serialVersionUID = 1L;


    /**
     * The Content Encryption Key (CEK) bit length, zero if not specified.
     */
    private final int cekBitLength;


    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 256 bit
     * key (required).
     */
    public static final EncryptionMethod A128CBC_HS256 =
            new EncryptionMethod("A128CBC-HS256", 256);


    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption using a 384 bit
     * key (optional).
     */
    public static final EncryptionMethod A192CBC_HS384 =
            new EncryptionMethod("A192CBC-HS384", 384);


    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit
     * key (required).
     */
    public static final EncryptionMethod A256CBC_HS512 =
            new EncryptionMethod("A256CBC-HS512", 512);


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 128 bit key
     * (recommended).
     */
    public static final EncryptionMethod A128GCM =
            new EncryptionMethod("A128GCM", 128);


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 192 bit key
     * (optional).
     */
    public static final EncryptionMethod A192GCM =
            new EncryptionMethod("A192GCM", 192);


    /**
     * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 256 bit key
     * (recommended).
     */
    public static final EncryptionMethod A256GCM =
            new EncryptionMethod("A256GCM", 256);


    /**
     * Encryption method family.
     */
    public static final class Family extends AlgorithmFamily<EncryptionMethod> {


        private static final long serialVersionUID = 1L;


        /**
         * AES/CBC/HMAC with SHA-2.
         */
        public static final Family AES_CBC_HMAC_SHA = new Family(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512);


        /**
         * AES/GCM.
         */
        public static final Family AES_GCM = new Family(A128GCM, A192GCM, A256GCM);


        /***
         * Creates a new encryption method family.
         *
         * @param encs The encryption methods of the family. Must not
         *             be {@code null}.
         */
        public Family(EncryptionMethod... encs) {
            super(encs);
        }
    }


    /**
     * Creates a new encryption method.
     *
     * @param name         The encryption method name. Must not be
     *                     {@code null}.
     * @param cekBitLength The Content Encryption Key (CEK) bit length,
     *                     zero if not specified.
     */
    public EncryptionMethod(String name, int cekBitLength) {

        super(name);

        this.cekBitLength = cekBitLength;
    }


    /**
     * Creates a new encryption method. The Content Encryption Key (CEK)
     * bit length is not specified.
     *
     * @param name The encryption method name. Must not be {@code null}.
     */

    public EncryptionMethod(String name) {

        this(name, 0);
    }


    /**
     * Gets the length of the associated Content Encryption Key (CEK).
     *
     * @return The Content Encryption Key (CEK) bit length, zero if not
     * specified.
     */
    public int cekBitLength() {

        return cekBitLength;
    }


    /**
     * Parses an encryption method from the specified string.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The encryption method  (matching standard algorithm
     * constant, else a newly created algorithm).
     */
    public static EncryptionMethod parse(String value) {

        if (value.equals(A128CBC_HS256.getName())) {

            return A128CBC_HS256;

        } else if (value.equals(A192CBC_HS384.getName())) {

            return A192CBC_HS384;

        } else if (value.equals(A256CBC_HS512.getName())) {

            return A256CBC_HS512;

        } else if (value.equals(A128GCM.getName())) {

            return A128GCM;

        } else if (value.equals(A192GCM.getName())) {

            return A192GCM;

        } else if (value.equals(A256GCM.getName())) {

            return A256GCM;

        } else {

            return new EncryptionMethod(value);
        }
    }
}
