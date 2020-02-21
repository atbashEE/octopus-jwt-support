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


import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;

import javax.crypto.SecretKey;
import java.util.*;


/**
 * The base abstract class for AES and AES GCM key wrap encrypters and
 * decrypters of {@link JWEObject JWE objects}.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *      <li>{@link JWEAlgorithm#A128KW}
 *      <li>{@link JWEAlgorithm#A192KW}
 *      <li>{@link JWEAlgorithm#A256KW}
 *      <li>{@link JWEAlgorithm#A128GCMKW}
 *      <li>{@link JWEAlgorithm#A192GCMKW}
 *      <li>{@link JWEAlgorithm#A256GCMKW}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link EncryptionMethod#A128CBC_HS256}
 *     <li>{@link EncryptionMethod#A192CBC_HS384}
 *     <li>{@link EncryptionMethod#A256CBC_HS512}
 *     <li>{@link EncryptionMethod#A128GCM}
 *     <li>{@link EncryptionMethod#A192GCM}
 *     <li>{@link EncryptionMethod#A256GCM}
 * </ul>
 *
 * Based on code by Melisa Halsband and Vladimir Dzhuvinov
 */
public abstract class AESCryptoProvider extends BaseJWEProvider {


    /**
     * The supported JWE algorithms by the AES crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods by the AES crypto provider class.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


    /**
     * The JWE algorithms compatible with each key size in bits.
     */
    private static final Map<Integer, Set<JWEAlgorithm>> COMPATIBLE_ALGORITHMS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.A128KW);
        algs.add(JWEAlgorithm.A192KW);
        algs.add(JWEAlgorithm.A256KW);
        algs.add(JWEAlgorithm.A128GCMKW);
        algs.add(JWEAlgorithm.A192GCMKW);
        algs.add(JWEAlgorithm.A256GCMKW);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

        Map<Integer, Set<JWEAlgorithm>> algsMap = new HashMap<>();
        Set<JWEAlgorithm> bit128Algs = new HashSet<>();
        Set<JWEAlgorithm> bit192Algs = new HashSet<>();
        Set<JWEAlgorithm> bit256Algs = new HashSet<>();
        bit128Algs.add(JWEAlgorithm.A128GCMKW);
        bit128Algs.add(JWEAlgorithm.A128KW);
        bit192Algs.add(JWEAlgorithm.A192GCMKW);
        bit192Algs.add(JWEAlgorithm.A192KW);
        bit256Algs.add(JWEAlgorithm.A256GCMKW);
        bit256Algs.add(JWEAlgorithm.A256KW);
        algsMap.put(128, Collections.unmodifiableSet(bit128Algs));
        algsMap.put(192, Collections.unmodifiableSet(bit192Algs));
        algsMap.put(256, Collections.unmodifiableSet(bit256Algs));
        COMPATIBLE_ALGORITHMS = Collections.unmodifiableMap(algsMap);
    }


    /**
     * The Key Encryption Key (KEK).
     */
    private final SecretKey kek;


    /**
     * Returns the compatible JWE algorithms for the specified Key
     * Encryption Key (CEK) length.
     *
     * @param kekLength The KEK length in bits.
     * @return The compatible JWE algorithms.
     */
    private static Set<JWEAlgorithm> getCompatibleJWEAlgorithms(int kekLength) {

        Set<JWEAlgorithm> algs = COMPATIBLE_ALGORITHMS.get(kekLength);

        if (algs == null) {
            throw new KeyLengthException("The Key Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes)");
        }

        return algs;
    }


    /**
     * Creates a new AES encryption / decryption provider.
     *
     * @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192
     *            bits (24 bytes) or 256 bits (32 bytes). Must not be
     *            {@code null}.
     */
    protected AESCryptoProvider(SecretKey kek) {

        super(getCompatibleJWEAlgorithms(ByteUtils.bitLength(kek.getEncoded())), ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

        this.kek = kek;
    }


    /**
     * Gets the Key Encryption Key (KEK).
     *
     * @return The Key Encryption Key.
     */
    public SecretKey getKey() {

        return kek;
    }
}
