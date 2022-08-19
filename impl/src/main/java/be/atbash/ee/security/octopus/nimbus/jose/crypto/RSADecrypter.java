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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.*;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Set;


/**
 * RSA decrypter of {@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject JWE objects}. Expects a
 * private RSA key.
 *
 * <p>Decrypts the encrypted Content Encryption Key (CEK) with the private RSA
 * key, and then uses the CEK along with the IV and authentication tag to
 * decrypt the cipher text. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.2">4.2</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.3">4.3</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#RSA_OAEP_256}
 *     <li>{@link JWEAlgorithm#RSA_OAEP_384}
 *     <li>{@link JWEAlgorithm#RSA_OAEP_512}
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
 * Based on code by David Ortiz, Vladimir Dzhuvinov and Dimitar A. Stoikov
 */
public class RSADecrypter extends RSACryptoProvider implements JWEDecrypter {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * The private RSA key.
     */
    private final PrivateKey privateKey;

    /**
     * Creates a new RSA decrypter. This constructor can also accept a
     * private RSA key located in a PKCS#11 store that doesn't expose the
     * private key parameters (such as a smart card or HSM).
     *
     * @param privateKey The private RSA key. Its algorithm must be "RSA"
     *                   and its length at least 2048 bits. Note that the
     *                   length of an RSA key in a PKCS#11 store cannot be
     *                   checked. Must not be {@code null}.
     */
    public RSADecrypter(PrivateKey privateKey) {

        this(privateKey, null, false);
    }


    /**
     * Creates a new RSA decrypter.
     *
     * @param rsaJWK The RSA JSON Web Key (JWK). Must contain or reference
     *               a private part. Its length must be at least 2048 bits.
     *               Note that the length of an RSA key in a PKCS#11 store
     *               cannot be checked. Must not be {@code null}.
     */
    public RSADecrypter(RSAKey rsaJWK) {

        this(RSAKeyUtils.toRSAPrivateKey(rsaJWK));
    }


    /**
     * Creates a new RSA decrypter. This constructor can also accept a
     * private RSA key located in a PKCS#11 store that doesn't expose the
     * private key parameters (such as a smart card or HSM).
     *
     * @param privateKey     The private RSA key. Its algorithm must be
     *                       "RSA" and its length at least 2048 bits. Note
     *                       that the length of an RSA key in a PKCS#11
     *                       store cannot be checked. Must not be
     *                       {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     */
    public RSADecrypter(PrivateKey privateKey,
                        Set<String> defCritHeaders) {

        this(privateKey, defCritHeaders, false);
    }


    /**
     * Creates a new RSA decrypter. This constructor can also accept a
     * private RSA key located in a PKCS#11 store that doesn't expose the
     * private key parameters (such as a smart card or HSM).
     *
     * @param privateKey     The private RSA key. Its algorithm must be
     *                       "RSA" and its length at least 2048 bits. Note
     *                       that the length of an RSA key in a PKCS#11
     *                       store cannot be checked. Must not be
     *                       {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @param allowWeakKey   {@code true} to allow an RSA key shorter than
     *                       2048 bits.
     */
    public RSADecrypter(PrivateKey privateKey,
                        Set<String> defCritHeaders,
                        boolean allowWeakKey) {

        if (!privateKey.getAlgorithm().equalsIgnoreCase(JWKIdentifiers.RSA_KEY_TYPE)) {
            throw new IllegalArgumentException("The private key algorithm must be RSA");
        }

        if (!allowWeakKey) {

            int keyBitLength = RSAKeyUtils.keyBitLength(privateKey);

            if (keyBitLength > 0 && keyBitLength < RSASSASigner.MIN_KEY_SIZE_BITS) {
                throw new IllegalArgumentException("The RSA key size must be at least " + RSASSASigner.MIN_KEY_SIZE_BITS + " bits");
            }
        }

        this.privateKey = privateKey;

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }


    /**
     * Gets the private RSA key.
     *
     * @return The private RSA key. Casting to
     * {@link java.security.interfaces.RSAPrivateKey} may not be
     * possible if the key is located in a PKCS#11 store that
     * doesn't expose the private key parameters.
     */
    public PrivateKey getPrivateKey() {

        return privateKey;
    }

    @Override
    public byte[] decrypt(JWEHeader header,
                          Base64URLValue encryptedKey,
                          Base64URLValue iv,
                          Base64URLValue cipherText,
                          Base64URLValue authTag) {

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

        SecretKey cek = RSA_OAEP_2.decryptCEK(privateKey, encryptedKey.decode(), alg);

        return ContentCryptoProvider.decrypt(header, iv, cipherText, authTag, cek);
    }
}

