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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ContentCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.DirectCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Set;


/**
 * Direct decrypter of {@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject JWE objects} with a
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
 * <p>Also supports a promiscuous mode to decrypt any JWE by passing the
 * content encryption key (CEK) directly. The that mode the JWE algorithm
 * checks for ("alg":"dir") and encrypted key not being present will be
 * skipped.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class DirectDecrypter extends DirectCryptoProvider implements JWEDecrypter {


    /**
     * If set skips the checks for alg "dir" and encrypted key not present.
     */
    private final boolean promiscuousMode;


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * Creates a new direct decrypter.
     *
     * @param key The symmetric key. Its algorithm should be "AES". Must be
     *            128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32
     *            bytes), 384 bits (48 bytes) or 512 bits (64 bytes) long.
     *            Must not be {@code null}.
     */
    public DirectDecrypter(SecretKey key) {

        this(key, false);
    }


    /**
     * Creates a new direct decrypter with the option to set it in
     * promiscuous mode.
     *
     * @param key             The symmetric key. Its algorithm should be
     *                        "AES". Must be 128 bits (16 bytes), 192 bits
     *                        (24 bytes), 256 bits (32 bytes), 384 bits (48
     *                        bytes) or 512 bits (64 bytes) long. Must not
     *                        be {@code null}.
     * @param promiscuousMode If {@code true} set the decrypter in
     *                        promiscuous mode to permit decryption of any
     *                        JWE with the supplied symmetric key. The that
     *                        mode the JWE algorithm checks for
     *                        ("alg":"dir") and encrypted key not being
     *                        present will be skipped.
     */
    public DirectDecrypter(SecretKey key, boolean promiscuousMode) {

        super(key);

        this.promiscuousMode = promiscuousMode;
    }


    /**
     * Creates a new direct decrypter.
     *
     * @param keyBytes The symmetric key, as a byte array. Must be 128 bits
     *                 (16 bytes), 192 bits (24 bytes), 256 bits (32
     *                 bytes), 384 bits (48 bytes) or 512 bits (64 bytes)
     *                 long. Must not be {@code null}.
     */
    public DirectDecrypter(byte[] keyBytes) {

        this(new SecretKeySpec(keyBytes, "AES"), false);
    }


    /**
     * Creates a new direct decrypter.
     *
     * @param octJWK The symmetric key, as a JWK. Must be 128 bits (16
     *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
     *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
     *               be {@code null}.
     */
    public DirectDecrypter(OctetSequenceKey octJWK) {

        this(octJWK.toSecretKey());
    }


    /**
     * Creates a new direct decrypter with the option to set it in
     * promiscuous mode.
     *
     * @param key            The symmetric key. Its algorithm should be
     *                       "AES". Must be 128 bits (16 bytes), 192 bits
     *                       (24 bytes), 256 bits (32 bytes), 384 bits (48
     *                       bytes) or 512 bits (64 bytes) long. Must not
     *                       be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public DirectDecrypter(SecretKey key, Set<String> defCritHeaders) {

        this(key, defCritHeaders, false);
    }


    /**
     * Creates a new direct decrypter.
     *
     * @param key             The symmetric key. Its algorithm should be
     *                        "AES". Must be 128 bits (16 bytes), 192 bits
     *                        (24 bytes), 256 bits (32 bytes), 384 bits (48
     *                        bytes) or 512 bits (64 bytes) long. Must not
     *                        be {@code null}.
     * @param defCritHeaders  The names of the critical header parameters
     *                        that are deferred to the application for
     *                        processing, empty set or {@code null} if none.
     * @param promiscuousMode If {@code true} set the decrypter in
     *                        promiscuous mode to permit decryption of any
     *                        JWE with the supplied symmetric key. In that
     *                        mode the JWE algorithm checks for
     *                        ("alg":"dir") and encrypted key not being
     *                        present will be skipped.
     */
    public DirectDecrypter(SecretKey key,
                           Set<String> defCritHeaders,
                           boolean promiscuousMode) {

        super(key);
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
        this.promiscuousMode = promiscuousMode;
    }

    @Override
    public byte[] decrypt(JWEHeader header,
                          Base64URLValue encryptedKey,
                          Base64URLValue iv,
                          Base64URLValue cipherText,
                          Base64URLValue authTag) {

        // Validate required JWE parts
        if (!promiscuousMode) {

            JWEAlgorithm alg = header.getAlgorithm();

            if (!alg.equals(JWEAlgorithm.DIR)) {
                throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
            }

            if (encryptedKey != null) {
                throw new JOSEException("Unexpected present JWE encrypted key");
            }
        }

        if (iv == null) {
            throw new JOSEException("Unexpected present JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        critPolicy.ensureHeaderPasses(header);

        return ContentCryptoProvider.decrypt(header, iv, cipherText, authTag, getKey());
    }
}
