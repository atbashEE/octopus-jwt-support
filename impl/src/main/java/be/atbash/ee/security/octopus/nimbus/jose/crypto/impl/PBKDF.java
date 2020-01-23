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


import be.atbash.util.exception.AtbashUnexpectedException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


/**
 * Password-Based Key Derivation Function (PBKDF) utilities. Provides static
 * methods to generate Key Encryption Keys (KEK) from passwords.
 */
public final class PBKDF {

    private static final String AES = "AES";


    /**
     * Prevents public instantiation.
     */
    private PBKDF() {

    }

    /**
     * Derives a PBKDF2 key from the specified password and parameters.
     *
     * @param password       The password. Must not be {@code null}.
     * @param saltBytes      The formatted cryptographic salt. Must not be
     *                       {@code null}.
     * @param iterationCount The iteration count. Must be positive.
     * @param prfParams      The Pseudo-Random Function (PRF) parameters.
     *                       Must not be {@code null}.
     * @return The derived secret key (with "AES" algorithm).
     */
    public static SecretKey deriveKey(char[] password,
                                      byte[] saltBytes,
                                      int iterationCount,
                                      PRFParams prfParams) {

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(prfParams.getMACAlgorithm());
            PBEKeySpec spec = new PBEKeySpec(password, saltBytes, iterationCount, prfParams.getDerivedKeyByteLength() * 8);
            SecretKey secretKey = factory.generateSecret(spec);
            return new SecretKeySpec(secretKey.getEncoded(), AES);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

}
