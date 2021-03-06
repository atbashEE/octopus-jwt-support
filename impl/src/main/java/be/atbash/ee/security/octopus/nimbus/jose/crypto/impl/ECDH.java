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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;


/**
 * Elliptic Curve Diffie-Hellman key agreement functions and utilities.
 *
 * Based on code by Vladimir Dzhuvinov
 */
// FIXME Move to Key-server / diffieHellman Project? Seems to be used by encrypter and decrypter
public final class ECDH {


    /**
     * Enumeration of the Elliptic Curve Diffie-Hellman Ephemeral Static
     * algorithm modes.
     */
    public enum AlgorithmMode {

        /**
         * Direct key agreement mode.
         */
        DIRECT,


        /**
         * Key wrapping mode.
         */
        KW
    }


    /**
     * Resolves the ECDH algorithm mode.
     *
     * @param alg The JWE algorithm. Must be supported and not
     *            {@code null}.
     * @return The algorithm mode.
     */
    public static AlgorithmMode resolveAlgorithmMode(JWEAlgorithm alg) {

        if (alg.equals(JWEAlgorithm.ECDH_ES)) {

            return AlgorithmMode.DIRECT;

        } else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW) ||
                alg.equals(JWEAlgorithm.ECDH_ES_A192KW) ||
                alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {

            return AlgorithmMode.KW;
        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
                    alg,
                    ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
        }
    }


    /**
     * Returns the bit length of the shared key (derived via concat KDF)
     * for the specified JWE ECDH algorithm.
     *
     * @param alg The JWE ECDH algorithm. Must be supported and not
     *            {@code null}.
     * @param enc The encryption method. Must be supported} and not
     *            {@code null}.
     * @return The bit length of the shared key.
     */
    public static int sharedKeyLength(JWEAlgorithm alg, EncryptionMethod enc) {

        if (alg.equals(JWEAlgorithm.ECDH_ES)) {

            int length = enc.cekBitLength();

            if (length == 0) {
                throw new JOSEException("Unsupported JWE encryption method " + enc);
            }

            return length;

        } else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW)) {
            return 128;
        } else if (alg.equals(JWEAlgorithm.ECDH_ES_A192KW)) {
            return 192;
        } else if (alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {
            return 256;
        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
                    alg, ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
        }
    }


    /**
     * Derives a shared secret (also called 'Z') from the specified ECDH
     * key agreement.
     *
     * @param publicKey  The public EC key, i.e. the consumer's public EC
     *                   key on encryption, or the ephemeral public EC key
     *                   on decryption. Must not be {@code null}.
     * @param privateKey The private EC Key, i.e. the ephemeral private EC
     *                   key on encryption, or the consumer's private EC
     *                   key on decryption. Must not be {@code null}.
     * @return The derived shared secret ('Z'), with algorithm "AES".
     */
    public static SecretKey deriveSharedSecret(ECPublicKey publicKey,
                                               PrivateKey privateKey) {

        // Get an ECDH key agreement instance from the JCA provider
        KeyAgreement keyAgreement;

        try {

            keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProviderSingleton.getInstance());

        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't get an ECDH key agreement instance: " + e.getMessage(), e);
        }

        try {
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid key for ECDH key agreement: " + e.getMessage(), e);
        }

        return new SecretKeySpec(keyAgreement.generateSecret(), "AES");
    }

    /**
     * Derives a shared key (via concat KDF).
     *
     * @param header    The JWE header. Its algorithm and encryption method
     *                  must be supported. Must not be {@code null}.
     * @param Z         The derived shared secret ('Z'). Must not be
     *                  {@code null}.
     * @param concatKDF The concat KDF. Must be initialised and not
     *                  {@code null}.
     * @return The derived shared key.
     */
    public static SecretKey deriveSharedKey(JWEHeader header,
                                            SecretKey Z,
                                            ConcatKDF concatKDF) {

        int sharedKeyLength = sharedKeyLength(header.getAlgorithm(), header.getEncryptionMethod());

        // Set the alg ID for the concat KDF
        AlgorithmMode algMode = resolveAlgorithmMode(header.getAlgorithm());

        String algID;

        if (algMode == AlgorithmMode.DIRECT) {
            // algID = enc
            algID = header.getEncryptionMethod().getName();
        } else if (algMode == AlgorithmMode.KW) {
            // algID = alg
            algID = header.getAlgorithm().getName();
        } else {
            throw new JOSEException("Unsupported JWE ECDH algorithm mode: " + algMode);
        }

        return concatKDF.deriveKey(
                Z,
                sharedKeyLength,
                ConcatKDF.encodeDataWithLength(algID.getBytes(StandardCharsets.US_ASCII)),
                ConcatKDF.encodeDataWithLength(header.getAgreementPartyUInfo()),
                ConcatKDF.encodeDataWithLength(header.getAgreementPartyVInfo()),
                ConcatKDF.encodeIntData(sharedKeyLength),
                ConcatKDF.encodeNoData());
    }


    /**
     * Prevents public instantiation.
     */
    private ECDH() {

    }
}
