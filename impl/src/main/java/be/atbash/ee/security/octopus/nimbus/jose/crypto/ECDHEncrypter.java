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
import be.atbash.ee.security.octopus.nimbus.jose.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jose.JWEEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDH;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDHCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.ECKey;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman encrypter of
 * {@link be.atbash.ee.security.octopus.nimbus.jose.JWEObject JWE objects} for curves using EC JWK keys.
 * Expects a public EC key (with a P-256, P-384 or P-521 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.6">section 4.6</a>
 * for more information.
 *
 * <p>For Curve25519/X25519, see {@link X25519Encrypter} instead.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#ECDH_ES}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve#P_256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve#P_384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve#P_521}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A192GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256GCM}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link be.atbash.ee.security.octopus.nimbus.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Tim McLean
 * @author Vladimir Dzhuvinov
 * @author Fernando González Callejas
 * @version 2019-01-24
 */
public class ECDHEncrypter extends ECDHCryptoProvider implements JWEEncrypter {


    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    public static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES;


    static {
        Set<Curve> curves = new LinkedHashSet<>();
        curves.add(Curve.P_256);
        curves.add(Curve.P_384);
        curves.add(Curve.P_521);
        SUPPORTED_ELLIPTIC_CURVES = Collections.unmodifiableSet(curves);
    }


    /**
     * The public EC key.
     */
    private final ECPublicKey publicKey;

    /**
     * The externally supplied AES content encryption key (CEK) to use,
     * {@code null} to generate a CEK for each JWE.
     */
    private final SecretKey contentEncryptionKey;

    /**
     * Creates a new Elliptic Curve Diffie-Hellman encrypter.
     *
     * @param publicKey The public EC key. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHEncrypter(ECPublicKey publicKey)
            throws JOSEException {

        this(publicKey, null);
    }


    /**
     * Creates a new Elliptic Curve Diffie-Hellman encrypter.
     *
     * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHEncrypter(ECKey ecJWK) throws
            JOSEException {

        super(ecJWK.getCurve());

        publicKey = ecJWK.toECPublicKey();
        contentEncryptionKey = null;
    }

    /**
     * Creates a new Elliptic Curve Diffie-Hellman encrypter with an
     * optionally specified content encryption key (CEK).
     *
     * @param publicKey            The public EC key. Must not be
     *                             {@code null}.
     * @param contentEncryptionKey The content encryption key (CEK) to use.
     *                             If specified its algorithm must be "AES"
     *                             and its length must match the expected
     *                             for the JWE encryption method ("enc").
     *                             If {@code null} a CEK will be generated
     *                             for each JWE.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHEncrypter(ECPublicKey publicKey, final SecretKey contentEncryptionKey)
            throws JOSEException {

        super(Curve.forECParameterSpec(publicKey.getParams()));

        this.publicKey = publicKey;

        if (contentEncryptionKey != null) {
            if (contentEncryptionKey.getAlgorithm() == null || !contentEncryptionKey.getAlgorithm().equals("AES")) {
                throw new IllegalArgumentException("The algorithm of the content encryption key (CEK) must be AES");
            } else {
                this.contentEncryptionKey = contentEncryptionKey;
            }
        } else {
            this.contentEncryptionKey = null;
        }
    }


    /**
     * Returns the public EC key.
     *
     * @return The public EC key.
     */
    public ECPublicKey getPublicKey() {

        return publicKey;
    }


    @Override
    public Set<Curve> supportedEllipticCurves() {

        return SUPPORTED_ELLIPTIC_CURVES;
    }


    @Override
    public JWECryptoParts encrypt(JWEHeader header, final byte[] clearText)
            throws JOSEException {

        // Generate ephemeral EC key pair on the same curve as the consumer's public key
        KeyPair ephemeralKeyPair = generateEphemeralKeyPair(publicKey.getParams());
        ECPublicKey ephemeralPublicKey = (ECPublicKey) ephemeralKeyPair.getPublic();
        ECPrivateKey ephemeralPrivateKey = (ECPrivateKey) ephemeralKeyPair.getPrivate();

        // Add the ephemeral public EC key to the header
        JWEHeader updatedHeader = new JWEHeader.Builder(header).
                ephemeralPublicKey(new ECKey.Builder(getCurve(), ephemeralPublicKey).build()).
                build();

        // Derive 'Z'
        SecretKey Z = ECDH.deriveSharedSecret(
                publicKey,
                ephemeralPrivateKey,
                getJCAContext().getKeyEncryptionProvider());

        return encryptWithZ(updatedHeader, Z, clearText, contentEncryptionKey);
    }


    /**
     * Generates a new ephemeral EC key pair with the specified curve.
     *
     * @param ecParameterSpec The EC key spec. Must not be {@code null}.
     * @return The EC key pair.
     * @throws JOSEException If the EC key pair couldn't be generated.
     */
    private KeyPair generateEphemeralKeyPair(ECParameterSpec ecParameterSpec)
            throws JOSEException {

        Provider keProvider = getJCAContext().getKeyEncryptionProvider();

        try {
            KeyPairGenerator generator;

            if (keProvider != null) {
                generator = KeyPairGenerator.getInstance("EC", keProvider);
            } else {
                generator = KeyPairGenerator.getInstance("EC");
            }

            generator.initialize(ecParameterSpec);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new JOSEException("Couldn't generate ephemeral EC key pair: " + e.getMessage(), e);
        }
    }
}