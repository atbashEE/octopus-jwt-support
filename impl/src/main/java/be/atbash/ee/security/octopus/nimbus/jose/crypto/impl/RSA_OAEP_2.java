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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;


/**
 * RSAES OAEP (SHA-256) methods for Content Encryption Key (CEK) encryption and
 * decryption. Uses the BouncyCastle.org provider. This class is thread-safe
 * <p>
 * Based on code by Vladimir Dzhuvinov and Justin Richer
 */
public final class RSA_OAEP_2 {


    /**
     * The JCA algorithm name for RSA-OAEP-256.
     */
    private static final String RSA_OEAP_256_JCA_ALG = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * The JCA algorithm name for RSA-OAEP-384.
     */
    private static final String RSA_OEAP_384_JCA_ALG = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";

    /**
     * The JCA algorithm name for RSA-OAEP-512.
     */
    private static final String RSA_OEAP_512_JCA_ALG = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";


    /**
     * Encrypts the specified Content Encryption Key (CEK).
     *
     * @param pub          The public RSA key. Must not be {@code null}.
     * @param cek          The Content Encryption Key (CEK) to encrypt. Must
     *                     not be {@code null}.
     * @param jweAlgorithm JWE Algorithm to use (256 or 512)
     * @return The encrypted Content Encryption Key (CEK).
     */
    public static byte[] encryptCEK(RSAPublicKey pub, SecretKey cek, JWEAlgorithm jweAlgorithm) {

        try {
            AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP");
            AlgorithmParameterSpec paramSpec = getParameterSpec(jweAlgorithm);
            algp.init(paramSpec);
            Cipher cipher = getCipher(jweAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, pub, algp);
            return cipher.doFinal(cek.getEncoded());

        } catch (IllegalBlockSizeException e) {
            throw new JOSEException("RSA block size exception: The RSA key is too short, try a longer one", e);
        } catch (Exception e) {
            // java.security.NoSuchAlgorithmException
            // java.security.NoSuchPaddingException
            // java.security.InvalidKeyException
            // javax.crypto.BadPaddingException
            throw new JOSEException(e.getMessage(), e);
        }
    }

    private static Cipher getCipher(JWEAlgorithm jweAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_256) {
            return CipherHelper.getInstance(RSA_OEAP_256_JCA_ALG);
        }
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_384) {
            return CipherHelper.getInstance(RSA_OEAP_384_JCA_ALG);
        }
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_512) {
            return CipherHelper.getInstance(RSA_OEAP_512_JCA_ALG);
        }
        // Unexpected as this should already be caught by getParameterSpec
        throw new AtbashUnexpectedException(String.format("The JWE Algorithm '%s' is not recognised", jweAlgorithm.getName()));
    }

    private static OAEPParameterSpec getParameterSpec(JWEAlgorithm jweAlgorithm) {
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_256) {
            return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        }
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_384) {
            return new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT);
        }
        if (jweAlgorithm == JWEAlgorithm.RSA_OAEP_512) {
            return new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        }
        throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(jweAlgorithm, RSACryptoProvider.SUPPORTED_ALGORITHMS));
    }


    /**
     * Decrypts the specified encrypted Content Encryption Key (CEK).
     *
     * @param priv         The private RSA key. Must not be {@code null}.
     * @param encryptedCEK The encrypted Content Encryption Key (CEK) to
     *                     decrypt. Must not be {@code null}.
     * @param jweAlgorithm JWE Algorithm
     * @return The decrypted Content Encryption Key (CEK).
     */
    public static SecretKey decryptCEK(PrivateKey priv,
                                       byte[] encryptedCEK,
                                       JWEAlgorithm jweAlgorithm) {

        try {
            AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP");
            AlgorithmParameterSpec paramSpec = getParameterSpec(jweAlgorithm);
            algp.init(paramSpec);
            Cipher cipher = getCipher(jweAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, priv, algp);
            return new SecretKeySpec(cipher.doFinal(encryptedCEK), "AES");

        } catch (Exception e) {
            // java.security.NoSuchAlgorithmException
            // java.security.NoSuchPaddingException
            // java.security.InvalidKeyException
            // javax.crypto.IllegalBlockSizeException
            // javax.crypto.BadPaddingException
            throw new JOSEException(e.getMessage(), e);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private RSA_OAEP_2() {
    }
}