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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;


/**
 * Pseudo-Random Function (PRF) parameters, intended for use in the Password-
 * Based Key Derivation Function 2 (PBKDF2).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-26
 */
public final class PRFParams {


    /**
     * The JCA MAC algorithm name.
     */
    private final String jcaMacAlg;


    /**
     * The byte length of the key to derive.
     */
    private final int dkLen;


    /**
     * Creates a new pseudo-random function parameters instance.
     *
     * @param jcaMacAlg The JCA MAC algorithm name. Must not be
     *                  {@code null}.
     * @param dkLen     The byte length of the key to derive.
     */
    public PRFParams(String jcaMacAlg, int dkLen) {
        this.jcaMacAlg = jcaMacAlg;
        this.dkLen = dkLen;
    }


    /**
     * Returns the JCA MAC algorithm name.
     *
     * @return The JCA MAC algorithm name.
     */
    public String getMACAlgorithm() {

        return jcaMacAlg;
    }


    /**
     * Returns the byte length of the key to derive.
     *
     * @return The byte length of the key to derive.
     */
    public int getDerivedKeyByteLength() {

        return dkLen;
    }


    /**
     * Resolves the Pseudo-Random Function (PRF) parameters for the
     * specified PBES2 JWE algorithm.
     *
     * @param alg The JWE algorithm. Must be supported and not
     *            {@code null}.
     * @return The PRF parameters.
     * @throws JOSEException If the JWE algorithm is not supported.
     */
    public static PRFParams resolve(JWEAlgorithm alg)
            throws JOSEException {

        String jcaMacAlg;
        int dkLen;

        if (JWEAlgorithm.PBES2_HS256_A128KW.equals(alg)) {
            jcaMacAlg = "PBKDF2WithHmacSHA1";  // FIXME Review logic of length and SHA512?
            dkLen = 16;
        } else if (JWEAlgorithm.PBES2_HS384_A192KW.equals(alg)) {
            jcaMacAlg = "PBKDF2WithHmacSHA1";
            dkLen = 24;
        } else if (JWEAlgorithm.PBES2_HS512_A256KW.equals(alg)) {
            jcaMacAlg = "PBKDF2WithHmacSHA1";
            dkLen = 32;
        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
                    alg,
                    PasswordBasedCryptoProvider.SUPPORTED_ALGORITHMS));
        }

        return new PRFParams(jcaMacAlg, dkLen);
    }
}
