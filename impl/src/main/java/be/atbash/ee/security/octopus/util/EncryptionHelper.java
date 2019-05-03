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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.exception.DecryptionFailedException;
import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

@PublicAPI
public final class EncryptionHelper {

    private static final String PBKDF_ALGO = "PBKDF2WithHmacSHA1";
    private static final int ITERATION_COUNT = 65556;
    private static final int KEYSIZE = 256;
    private static final String AES = "AES";
    private static final String AES_ALGO = "AES/CBC/PKCS5Padding"; // TODO Config
                  // This is maybe a bit better AES/GCM/NoPadding -> for 1.0 version as breaking change.

    private static final SecureRandom random = new SecureRandom();

    private EncryptionHelper() {
    }

    public static String encode(String value, char[] password) {
        return encode(value.getBytes(StandardCharsets.UTF_8), password);
    }

    public static String encode(byte[] value, char[] password) {
        if (StringUtils.isEmpty(password)) {
            throw new MissingPasswordException(MissingPasswordException.ObjectType.ENCRYPTION);
        }

        // generate correct cipher key for AES, based on the supplied PW.
        byte[] saltBytes = new byte[20];
        random.nextBytes(saltBytes);

        try {
            // Derive the key
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_ALGO);
            PBEKeySpec spec = new PBEKeySpec(password, saltBytes, ITERATION_COUNT, KEYSIZE);
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), AES);

            //encrypting the word
            Cipher cipher = Cipher.getInstance(AES_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            AlgorithmParameters params = cipher.getParameters();
            byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] encryptedTextBytes = cipher.doFinal(value);

            //prepend salt and vi
            byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
            System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
            System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
            System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
            return Base64.getEncoder().encodeToString(buffer);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | InvalidParameterSpecException | BadPaddingException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    public static String decode(String encryptedText, char[] password) {
        if (StringUtils.isEmpty(password)) {
            throw new MissingPasswordException(MissingPasswordException.ObjectType.ENCRYPTION);
        }

        byte[] decryptedTextBytes;
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGO);
            //strip off the salt and iv
            ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedText));
            byte[] saltBytes = new byte[20];
            buffer.get(saltBytes, 0, saltBytes.length);
            byte[] ivBytes = new byte[cipher.getBlockSize()];
            buffer.get(ivBytes, 0, ivBytes.length);
            byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];

            buffer.get(encryptedTextBytes);
            // Deriving the key
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_ALGO);
            PBEKeySpec spec = new PBEKeySpec(password, saltBytes, ITERATION_COUNT, 256);
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), AES);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (BadPaddingException e) {
            // BadPaddingException -> Wrong PW
            throw new DecryptionFailedException();
        } catch (IllegalBlockSizeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException e) {
            throw new AtbashUnexpectedException(e);
        }

        return new String(decryptedTextBytes);
    }

    public static String encode(String value, SecretKey secretKey) {
        return encode(value.getBytes(StandardCharsets.UTF_8), secretKey);
    }

    public static String encode(byte[] value, SecretKey secretKey) {

        byte[] saltBytes = new byte[20];
        random.nextBytes(saltBytes);

        try {

            //encrypting the word
            Cipher cipher = Cipher.getInstance(AES_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            AlgorithmParameters params = cipher.getParameters();
            byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] encryptedTextBytes = cipher.doFinal(value);

            //prepend salt and vi
            byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
            System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
            System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
            System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | InvalidParameterSpecException | BadPaddingException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    public static String decode(String encryptedText, SecretKey secretKey) {

        byte[] decryptedTextBytes;
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGO);
            //strip off the salt and iv
            ByteBuffer buffer = ByteBuffer.wrap(Base64.getUrlDecoder().decode(encryptedText));
            byte[] saltBytes = new byte[20];
            buffer.get(saltBytes, 0, saltBytes.length);
            byte[] ivBytes = new byte[cipher.getBlockSize()];
            buffer.get(ivBytes, 0, ivBytes.length);
            byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];

            buffer.get(encryptedTextBytes);

            SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), AES);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (BadPaddingException e) {
            // BadPaddingException -> Wrong PW
            throw new DecryptionFailedException();
        } catch (IllegalBlockSizeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException e) {
            throw new AtbashUnexpectedException(e);
        }

        return new String(decryptedTextBytes);
    }

}
