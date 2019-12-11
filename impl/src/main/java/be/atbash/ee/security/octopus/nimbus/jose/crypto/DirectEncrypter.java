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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ContentCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.DirectCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * Direct encrypter of {@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject JWE objects} with a
 * shared symmetric key.
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.5">section 4.5</a>
 * for more information.</p>
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#DIR}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A128CBC_HS256} (requires 256 bit key)
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A192CBC_HS384} (requires 384 bit key)
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A256CBC_HS512} (requires 512 bit key)
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A128GCM} (requires 128 bit key)
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A192GCM} (requires 192 bit key)
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A256GCM} (requires 256 bit key)
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-06-01
 */
public class DirectEncrypter extends DirectCryptoProvider implements JWEEncrypter {


    /**
     * Creates a new direct encrypter.
     *
     * @param key The symmetric key. Its algorithm should be "AES". Must be
     *            128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32
     *            bytes), 384 bits (48 bytes) or 512 bits (64 bytes) long.
     *            Must not be {@code null}.
     * @throws KeyLengthException If the symmetric key length is not
     *                            compatible.
     */
    public DirectEncrypter(SecretKey key)
            throws KeyLengthException {

        super(key);
    }


    /**
     * Creates a new direct encrypter.
     *
     * @param keyBytes The symmetric key, as a byte array. Must be 128 bits
     *                 (16 bytes), 192 bits (24 bytes), 256 bits (32
     *                 bytes), 384 bits (48 bytes) or 512 bits (64 bytes)
     *                 long. Must not be {@code null}.
     * @throws KeyLengthException If the symmetric key length is not
     *                            compatible.
     */
    public DirectEncrypter(byte[] keyBytes)
            throws KeyLengthException {

        this(new SecretKeySpec(keyBytes, "AES"));
    }


    /**
     * Creates a new direct encrypter.
     *
     * @param octJWK The symmetric key, as a JWK. Must be 128 bits (16
     *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
     *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
     *               be {@code null}.
     * @throws KeyLengthException If the symmetric key length is not
     *                            compatible.
     */
    public DirectEncrypter(OctetSequenceKey octJWK)
            throws KeyLengthException {

        this(octJWK.toSecretKey("AES"));
    }


    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText)
            throws JOSEException {

        JWEAlgorithm alg = header.getAlgorithm();

        if (!alg.equals(JWEAlgorithm.DIR)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }

        // Check key length matches encryption method
        EncryptionMethod enc = header.getEncryptionMethod();

        if (enc.cekBitLength() != ByteUtils.safeBitLength(getKey().getEncoded())) {
            throw new KeyLengthException(enc.cekBitLength(), enc);
        }

        Base64URLValue encryptedKey = null; // The second JWE part

        return ContentCryptoProvider.encrypt(header, clearText, getKey(), encryptedKey, getJCAContext());
    }
}