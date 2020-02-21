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


import be.atbash.ee.security.octopus.config.JCASupportConfiguration;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.Container;
import be.atbash.ee.security.octopus.nimbus.util.KeyUtils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;


/**
 * AES/GCM/NoPadding encryption and decryption methods.
 *
 * <p>See RFC 7518 (JWA), section 5.1 and appendix 3.
 *
 * Based on code by Vladimir Dzhuvinov, Axel Nennker and Dimitar A. Stoikov
 */
public final class AESGCM {


    /**
     * The standard Initialisation Vector (IV) length (96 bits).
     */
    private static final int IV_BIT_LENGTH = 96;


    /**
     * The standard authentication tag length (128 bits).
     */
    private static final int AUTH_TAG_BIT_LENGTH = 128;


    /**
     * Generates a random 96 bit (12 byte) Initialisation Vector(IV) for
     * use in AES-GCM encryption.
     *
     * <p>See RFC 7518 (JWA), section 5.3.
     *
     * @return The random 96 bit IV, as 12 byte array.
     */
    public static byte[] generateIV() {

        byte[] bytes = new byte[ByteUtils.byteLength(IV_BIT_LENGTH)];
        JCASupportConfiguration.getInstance().getSecureRandom().nextBytes(bytes);
        return bytes;
    }


    /**
     * Encrypts the specified plain text using AES/GCM/NoPadding.
     *
     * @param secretKey   The AES key. Must not be {@code null}.
     * @param plainText   The plain text. Must not be {@code null}.
     * @param ivContainer The initialisation vector (IV). Must not be
     *                    {@code null}. This is both input and output
     *                    parameter. On input, it carries externally
     *                    generated IV; on output, it carries the IV the
     *                    cipher actually used. JCA/JCE providers may
     *                    prefer to use an internally generated IV, e.g. as
     *                    described in
     *                    <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">NIST
     *                    Special Publication 800-38D </a>.
     * @param authData    The authenticated data. Must not be {@code null}.
     * @return The authenticated cipher text.
     */
    public static AuthenticatedCipherText encrypt(SecretKey secretKey,
                                                  Container<byte[]> ivContainer,
                                                  byte[] plainText,
                                                  byte[] authData) {

        // Key alg must be "AES"
        SecretKey aesKey = KeyUtils.toAESKey(secretKey);

        Cipher cipher;

        byte[] iv = ivContainer.get();

        try {

            cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProviderSingleton.getInstance());

            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_BIT_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {

            throw new JOSEException("Couldn't create AES/GCM/NoPadding cipher: " + e.getMessage(), e);

        }

        cipher.updateAAD(authData);

        byte[] cipherOutput;

        try {
            cipherOutput = cipher.doFinal(plainText);

        } catch (IllegalBlockSizeException | BadPaddingException e) {

            throw new JOSEException("Couldn't encrypt with AES/GCM/NoPadding: " + e.getMessage(), e);
        }

        int tagPos = cipherOutput.length - ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH);

        byte[] cipherText = ByteUtils.subArray(cipherOutput, 0, tagPos);
        byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH));

        // retrieve the actual IV used by the cipher -- it may be internally-generated.
        ivContainer.set(actualIVOf(cipher));

        return new AuthenticatedCipherText(cipherText, authTag);
    }


    /**
     * Retrieves the actual algorithm parameters and validates them.
     *
     * @param cipher The cipher to interrogate for the parameters it
     *               actually used.
     * @return The IV used by the specified cipher.
     * deemed unusable.
     * @see #actualParamsOf(Cipher)
     * @see #validate(byte[], int)
     */
    private static byte[] actualIVOf(Cipher cipher) {

        GCMParameterSpec actualParams = actualParamsOf(cipher);

        byte[] iv = actualParams.getIV();
        int tLen = actualParams.getTLen();

        validate(iv, tLen);

        return iv;
    }


    /**
     * Validates the specified IV and authentication tag according to the
     * AES GCM requirements in
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">JWA RFC</a>.
     *
     * @param iv            The IV to check for compliance.
     * @param authTagLength The authentication tag length to check for
     *                      compliance.
     * @see #IV_BIT_LENGTH
     * @see #AUTH_TAG_BIT_LENGTH
     */
    private static void validate(byte[] iv, int authTagLength) {

        if (ByteUtils.safeBitLength(iv) != IV_BIT_LENGTH) {
            throw new JOSEException(String.format("IV length of %d bits is required, got %d", IV_BIT_LENGTH, ByteUtils.safeBitLength(iv)));
        }

        if (authTagLength != AUTH_TAG_BIT_LENGTH) {
            throw new JOSEException(String.format("Authentication tag length of %d bits is required, got %d", AUTH_TAG_BIT_LENGTH, authTagLength));
        }
    }


    /**
     * Retrieves the actual AES GCM parameters used by the specified
     * cipher.
     *
     * @param cipher The cipher to interrogate. Non-{@code null}.
     * @return The AES GCM parameters. Non-{@code null}.
     */
    private static GCMParameterSpec actualParamsOf(Cipher cipher) {

        AlgorithmParameters algorithmParameters = cipher.getParameters();

        if (algorithmParameters == null) {
            throw new JOSEException("AES GCM ciphers are expected to make use of algorithm parameters");
        }

        try {
            // Note: GCMParameterSpec appears in Java 7
            return algorithmParameters.getParameterSpec(GCMParameterSpec.class);
        } catch (InvalidParameterSpecException shouldNotHappen) {
            throw new JOSEException(shouldNotHappen.getMessage(), shouldNotHappen);
        }
    }


    /**
     * Decrypts the specified cipher text using AES/GCM/NoPadding.
     *
     * @param secretKey  The AES key. Must not be {@code null}.
     * @param iv         The initialisation vector (IV). Must not be
     *                   {@code null}.
     * @param cipherText The cipher text. Must not be {@code null}.
     * @param authData   The authenticated data. Must not be {@code null}.
     * @param authTag    The authentication tag. Must not be {@code null}.
     * @return The decrypted plain text.
     */
    public static byte[] decrypt(SecretKey secretKey,
                                 byte[] iv,
                                 byte[] cipherText,
                                 byte[] authData,
                                 byte[] authTag) {

        // Key alg must be "AES"
        SecretKey aesKey = KeyUtils.toAESKey(secretKey);

        Cipher cipher;

        try {

            cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProviderSingleton.getInstance());

            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_BIT_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {

            throw new JOSEException("Couldn't create AES/GCM/NoPadding cipher: " + e.getMessage(), e);

        }

        cipher.updateAAD(authData);

        try {
            return cipher.doFinal(ByteUtils.concat(cipherText, authTag));

        } catch (IllegalBlockSizeException | BadPaddingException e) {

            throw new JOSEException("AES/GCM/NoPadding decryption failed: " + e.getMessage(), e);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private AESGCM() {
    }
}