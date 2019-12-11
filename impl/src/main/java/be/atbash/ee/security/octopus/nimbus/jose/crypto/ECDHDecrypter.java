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


import be.atbash.ee.security.octopus.nimbus.jose.CriticalHeaderParamsAware;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDH;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.ECDHCryptoProvider;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ECChecks;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman decrypter of
 * {@link JWEObject JWE objects} for curves using EC JWK
 * keys. Expects a private EC key (with a P-256, P-384 or P-521 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.6">section 4.6</a>
 * for more information.
 *
 * <p>For Curve25519/X25519, X25519Decrypter is not copied.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#ECDH_ES}
 *     <li>{@link JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256}
 *     <li>{@link Curve#P_384}
 *     <li>{@link Curve#P_521}
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
 * @author Vladimir Dzhuvinov
 * @version 2018-12-12
 */
public class ECDHDecrypter extends ECDHCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


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
     * The private EC key.
     */
    private final PrivateKey privateKey;


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter.
     *
     * @param privateKey The private EC key. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHDecrypter(ECPrivateKey privateKey)
            throws JOSEException {

        this(privateKey, null);
    }


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter.
     *
     * @param ecJWK The EC JSON Web Key (JWK). Must contain a private
     *              part. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHDecrypter(ECKey ecJWK)
            throws JOSEException {

        super(ecJWK.getCurve());

        if (!ecJWK.isPrivate()) {
            throw new JOSEException("The EC JWK doesn't contain a private part");
        }

        this.privateKey = ecJWK.toECPrivateKey();
    }


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter.
     *
     * @param privateKey     The private EC key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHDecrypter(ECPrivateKey privateKey, final Set<String> defCritHeaders)
            throws JOSEException {

        this(privateKey, defCritHeaders, Curve.forECParameterSpec(privateKey.getParams()));
    }


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter. This
     * constructor can also accept a private EC key located in a PKCS#11
     * store that doesn't expose the private key parameters (such as a
     * smart card or HSM).
     *
     * @param privateKey     The private EC key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @param curve          The key curve. Must not be {@code null}.
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDHDecrypter(PrivateKey privateKey,
                         Set<String> defCritHeaders,
                         Curve curve)
            throws JOSEException {

        super(curve);

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);

        this.privateKey = privateKey;
    }


    /**
     * Returns the private EC key.
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
    public Set<Curve> supportedEllipticCurves() {

        return SUPPORTED_ELLIPTIC_CURVES;
    }


    @Override
    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
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

        critPolicy.ensureHeaderPasses(header);

        // Get ephemeral EC key
        ECKey ephemeralKey = (ECKey) header.getEphemeralPublicKey();

        if (ephemeralKey == null) {
            throw new JOSEException("Missing ephemeral public EC key \"epk\" JWE header parameter");
        }

        ECPublicKey ephemeralPublicKey = ephemeralKey.toECPublicKey();

        // Curve check
        if (getPrivateKey() instanceof ECPrivateKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) getPrivateKey();
            if (!ECChecks.isPointOnCurve(ephemeralPublicKey, ecPrivateKey)) {
                throw new JOSEException("Invalid ephemeral public EC key: Point(s) not on the expected curve");
            }
        } else {
            if (!ECChecks.isPointOnCurve(ephemeralPublicKey, getCurve().toECParameterSpec())) {
                throw new JOSEException("Invalid ephemeral public EC key: Point(s) not on the expected curve");
            }
        }

        // Derive 'Z'
        SecretKey Z = ECDH.deriveSharedSecret(
                ephemeralPublicKey,
                privateKey,
                getJCAContext().getKeyEncryptionProvider());

        return decryptWithZ(header, Z, encryptedKey, iv, cipherText, authTag);
    }
}
