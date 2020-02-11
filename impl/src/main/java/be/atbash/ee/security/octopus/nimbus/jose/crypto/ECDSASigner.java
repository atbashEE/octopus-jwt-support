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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.config.JCASupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of
 * {@link JWSObject JWS objects}. Expects a private EC key
 * (with a P-256, P-384 or P-521 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.4">section 3.4</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#ES256}
 *     <li>{@link JWSAlgorithm#ES384}
 *     <li>{@link JWSAlgorithm#ES512}
 * </ul>
 *
 * Based on code by Axel Nennker and Vladimir Dzhuvinov
 */
public class ECDSASigner extends ECDSAProvider implements JWSSigner {


    /**
     * The private EC key. Represented by generic private key interface to
     * support key stores that prevent exposure of the private key
     * parameters via the {@link java.security.interfaces.RSAPrivateKey}
     * API.
     * <p>
     * See https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/169
     */
    private final PrivateKey privateKey;


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * signer.
     *
     * @param privateKey The private EC key. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSASigner(ECPrivateKey privateKey)
            throws JOSEException {

        super(ECDSA.resolveAlgorithm(privateKey));

        this.privateKey = privateKey;
    }

    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * signer.
     *
     * @param atbashKey The private EC key. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSASigner(AtbashKey atbashKey)
            throws JOSEException {

        this(getPrivateKey(atbashKey));
    }

    private static ECPrivateKey getPrivateKey(AtbashKey atbashKey) throws KeyTypeException {
        if (atbashKey.getSecretKeyType().getKeyType() != KeyType.EC) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PRIVATE) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        return (ECPrivateKey) atbashKey.getKey();
    }

    @Override
    public Base64URLValue sign(JWSHeader header, byte[] signingInput)
            throws JOSEException {

        JWSAlgorithm alg = header.getAlgorithm();

        if (!supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }

        // DER-encoded signature, according to JCA spec
        // (sequence of two integers - R + S)
        byte[] jcaSignature;

        try {
            Signature dsa = ECDSA.getSignerAndVerifier(alg);
            dsa.initSign(privateKey, JCASupportConfiguration.getInstance().getSecureRandom());
            dsa.update(signingInput);
            jcaSignature = dsa.sign();

        } catch (InvalidKeyException | SignatureException e) {

            throw new JOSEException(e.getMessage(), e);
        }

        int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
        byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(jcaSignature, rsByteArrayLength);
        return Base64URLValue.encode(jwsSignature);
    }
}
