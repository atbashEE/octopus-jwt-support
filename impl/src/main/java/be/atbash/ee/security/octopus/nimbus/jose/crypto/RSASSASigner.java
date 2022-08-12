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


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSAKeyUtils;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.RSASSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;


/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) signer of
 * {@link JWSObject JWS objects}. Expects a private RSA key.
 *
 * <p>See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3">3.3</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.5">3.5</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#RS256}
 *     <li>{@link JWSAlgorithm#RS384}
 *     <li>{@link JWSAlgorithm#RS512}
 *     <li>{@link JWSAlgorithm#PS256}
 *     <li>{@link JWSAlgorithm#PS384}
 *     <li>{@link JWSAlgorithm#PS512}
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov and Omer Levi Hevroni
 */
public class RSASSASigner extends RSASSAProvider implements JWSSigner {

    /**
     * The minimum size of generated keys.
     */
    public static final int MIN_KEY_SIZE_BITS = 2048;  // FIXME A better location for this, together with ECDHDecrypter.SUPPORTED_ELLIPTIC_CURVES
    //and ECDHEncrypter.SUPPORTED_ELLIPTIC_CURVES

    /**
     * The private RSA key. Represented by generic private key interface to
     * support key stores that prevent exposure of the private key
     * parameters via the {@link java.security.interfaces.RSAPrivateKey}
     * API.
     * <p>
     * See https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/169
     */
    private final RSAPrivateKey privateKey;


    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
     * This constructor can also accept a private RSA key located in a
     * PKCS#11 store that doesn't expose the private key parameters (such
     * as a smart card or HSM).
     *
     * @param privateKey The private RSA key. Its algorithm must be "RSA"
     *                   and its length at least 2048 bits. Note that the
     *                   length of an RSA key in a PKCS#11 store cannot be
     *                   checked. Must not be {@code null}.
     */
    public RSASSASigner(RSAPrivateKey privateKey) {

        this(privateKey, false);
    }

    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
     * This constructor can also accept a private RSA key located in a
     * PKCS#11 store that doesn't expose the private key parameters (such
     * as a smart card or HSM).
     *
     * @param atbashKey The private RSA key. Its algorithm must be "RSA"
     *                   and its length at least 2048 bits. Note that the
     *                   length of an RSA key in a PKCS#11 store cannot be
     *                   checked. Must not be {@code null}.
     */
    public RSASSASigner(AtbashKey atbashKey) {
        this(getPrivateKey(atbashKey));
    }

    private static RSAPrivateKey getPrivateKey(AtbashKey atbashKey) {
        if (atbashKey.getSecretKeyType().getKeyType() != KeyType.RSA) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PRIVATE) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        return (RSAPrivateKey) atbashKey.getKey();
    }

    /**
     * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
     * This constructor can also accept a private RSA key located in a
     * PKCS#11 store that doesn't expose the private key parameters (such
     * as a smart card or HSM).
     *
     * @param privateKey   The private RSA key. Its algorithm must be
     *                     "RSA" and its length at least 2048 bits. Note
     *                     that the length of an RSA key in a PKCS#11 store
     *                     cannot be checked. Must not be {@code null}.
     * @param allowWeakKey {@code true} to allow an RSA key shorter than
     *                     2048 bits.
     */
    public RSASSASigner(RSAPrivateKey privateKey, boolean allowWeakKey) {

        if (!JWKIdentifiers.RSA_KEY_TYPE.equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("The private key algorithm must be RSA");
        }

        if (!allowWeakKey) {

            int keyBitLength = RSAKeyUtils.keyBitLength(privateKey);

            if (keyBitLength > 0 && keyBitLength < MIN_KEY_SIZE_BITS) {
                throw new IllegalArgumentException("The RSA key size must be at least " + MIN_KEY_SIZE_BITS + " bits");
            }
        }

        this.privateKey = privateKey;
    }

    @Override
    public Base64URLValue sign(JWSHeader header, byte[] signingInput) {

        Signature signer = RSASSA.getSignerAndVerifier(header.getAlgorithm());

        try {
            signer.initSign(privateKey);
            signer.update(signingInput);
            return Base64URLValue.encode(signer.sign());

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid private RSA key: " + e.getMessage(), e);

        } catch (SignatureException e) {
            throw new JOSEException("RSA signature exception: " + e.getMessage(), e);
        }
    }
}
