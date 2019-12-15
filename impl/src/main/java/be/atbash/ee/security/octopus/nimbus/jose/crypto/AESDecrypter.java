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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.*;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Set;


/**
 * AES and AES GCM key wrap decrypter of {@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject JWE
 * objects}. Expects an AES key.
 *
 * <p>Unwraps the encrypted Content Encryption Key (CEK) with the specified AES
 * key, and then uses the CEK along with the IV and authentication tag to
 * decrypt the cipher text. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.4">4.4</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.7">4.7</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#A128KW}
 *     <li>{@link JWEAlgorithm#A192KW}
 *     <li>{@link JWEAlgorithm#A256KW}
 *     <li>{@link JWEAlgorithm#A128GCMKW}
 *     <li>{@link JWEAlgorithm#A192GCMKW}
 *     <li>{@link JWEAlgorithm#A256GCMKW}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A128GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A192GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod#A256GCM}
 * </ul>
 *
 * @author Melisa Halsband
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class AESDecrypter extends AESCryptoProvider implements JWEDecrypter {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * Creates a new AES decrypter.
     *
     * @param kek The Key Encrypting Key. Must be 128 bits (16 bytes), 192
     *            bits (24 bytes) or 256 bits (32 bytes). Must not be
     *            {@code null}.
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public AESDecrypter(SecretKey kek)
            throws KeyLengthException {

        this(kek, null);
    }


    /**
     * Creates a new AES decrypter.
     *
     * @param keyBytes The Key Encrypting Key, as a byte array. Must be 128
     *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
     *                 bytes). Must not be {@code null}.
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public AESDecrypter(byte[] keyBytes)
            throws KeyLengthException {

        this(new SecretKeySpec(keyBytes, "AES"));
    }


    /**
     * Creates a new AES decrypter.
     *
     * @param octJWK The Key Encryption Key, as a JWK. Must be 128 bits (16
     *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
     *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
     *               be {@code null}.
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public AESDecrypter(OctetSequenceKey octJWK)
            throws KeyLengthException {

        this(octJWK.toSecretKey("AES"));
    }


    /**
     * Creates a new AES decrypter.
     *
     * @param kek            The Key Encrypting Key. Must be 128 bits (16
     *                       bytes), 192 bits (24 bytes) or 256 bits (32
     *                       bytes). Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public AESDecrypter(SecretKey kek, Set<String> defCritHeaders)
            throws KeyLengthException {

        super(kek);

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }

    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public byte[] decrypt(JWEHeader header,
                          Base64URLValue encryptedKey,
                          Base64URLValue iv,
                          Base64URLValue cipherText,
                          Base64URLValue authTag)
            throws JOSEException {

        // Validate required JWE parts
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        critPolicy.ensureHeaderPasses(header);

        // Derive the content encryption key
        JWEAlgorithm alg = header.getAlgorithm();
        int keyLength = header.getEncryptionMethod().cekBitLength();

        SecretKey cek;

        if (alg.equals(JWEAlgorithm.A128KW) ||
                alg.equals(JWEAlgorithm.A192KW) ||
                alg.equals(JWEAlgorithm.A256KW)) {

            cek = AESKW.unwrapCEK(getKey(), encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());

        } else if (alg.equals(JWEAlgorithm.A128GCMKW) ||
                alg.equals(JWEAlgorithm.A192GCMKW) ||
                alg.equals(JWEAlgorithm.A256GCMKW)) {

            if (header.getIV() == null) {
                throw new JOSEException("Missing JWE \"iv\" header parameter");
            }

            byte[] keyIV = header.getIV().decode();

            if (header.getAuthTag() == null) {
                throw new JOSEException("Missing JWE \"tag\" header parameter");
            }

            byte[] keyTag = header.getAuthTag().decode();

            AuthenticatedCipherText authEncrCEK = new AuthenticatedCipherText(encryptedKey.decode(), keyTag);
            cek = AESGCMKW.decryptCEK(getKey(), keyIV, authEncrCEK, keyLength, getJCAContext().getKeyEncryptionProvider());

        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }

        return ContentCryptoProvider.decrypt(header, iv, cipherText, authTag, cek, getJCAContext());
    }
}