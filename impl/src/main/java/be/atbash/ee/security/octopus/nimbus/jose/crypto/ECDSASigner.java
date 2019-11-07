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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.AlgorithmSupportMessage;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSA;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECKey;
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
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 2016-11-30
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
     * signer. This constructor is intended for a private EC key located
     * in a PKCS#11 store that doesn't expose the private key parameters
     * (such as a smart card or HSM).
     *
     * @param privateKey The private EC key. Its algorithm must be "EC".
     *                   Must not be {@code null}.
     * @param curve      The elliptic curve for the key. Must not be
     *                   {@code null}.
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public ECDSASigner(PrivateKey privateKey, Curve curve)
            throws JOSEException {

        super(ECDSA.resolveAlgorithm(curve));

        if (!"EC".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("The private key algorithm must be EC");
        }

        this.privateKey = privateKey;
    }


    /**
     * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
     * signer.
     *
     * @param ecJWK The EC JSON Web Key (JWK). Must contain a private part.
     *              Must not be {@code null}.
     * @throws JOSEException If the EC JWK doesn't contain a private part,
     *                       its extraction failed, or the elliptic curve
     *                       is not supported.
     */
    public ECDSASigner(ECKey ecJWK)
            throws JOSEException {

        super(ECDSA.resolveAlgorithm(ecJWK.getCurve()));

        if (!ecJWK.isPrivate()) {
            throw new JOSEException("The EC JWK doesn't contain a private part");
        }

        privateKey = ecJWK.toPrivateKey();
    }


    /**
     * Gets the private EC key.
     *
     * @return The private EC key. Casting to
     * {@link ECPrivateKey} may not be
     * possible if the key is located in a PKCS#11 store that
     * doesn't expose the private key parameters.
     */
    public PrivateKey getPrivateKey() {

        return privateKey;
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
            Signature dsa = ECDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
            dsa.initSign(privateKey, getJCAContext().getSecureRandom());
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
