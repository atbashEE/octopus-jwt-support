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


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for Elliptic Curve Diffie-Hellman encrypters and
 * decrypters of {@link be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject JWE objects}.
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
 *     <li>{@link Curve#X25519}
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
 * Based on code by Tim McLean, Vladimir Dzhuvinov and Fernando González Callejas
 */
public abstract class ECDHCryptoProvider extends BaseJWEProvider {


    /**
     * The supported JWE algorithms by the ECDH crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods by the ECDH crypto provider class.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.ECDH_ES);
        algs.add(JWEAlgorithm.ECDH_ES_A128KW);
        algs.add(JWEAlgorithm.ECDH_ES_A192KW);
        algs.add(JWEAlgorithm.ECDH_ES_A256KW);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * The elliptic curve.
     */
    private final Curve curve;


    /**
     * The Concatenation Key Derivation Function (KDF).
     */
    private final ConcatKDF concatKDF;


    /**
     * Creates a new Elliptic Curve Diffie-Hellman encryption /decryption
     * provider.
     *
     * @param curve The elliptic curve. Must be supported and not
     *              {@code null}.
     */
    protected ECDHCryptoProvider(Curve curve) {

        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

        Curve definedCurve = curve != null ? curve : new Curve("unknown");

        if (!supportedEllipticCurves().contains(curve)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedEllipticCurve(
                    definedCurve, supportedEllipticCurves()));
        }

        this.curve = curve;

        concatKDF = new ConcatKDF("SHA-256");
    }


    /**
     * Returns the Concatenation Key Derivation Function (KDF).
     *
     * @return The concat KDF.
     */
    protected ConcatKDF getConcatKDF() {

        return concatKDF;
    }


    /**
     * Returns the names of the supported elliptic curves. These correspond
     * to the {@code crv} EC JWK parameter.
     *
     * @return The supported elliptic curves.
     */
    public abstract Set<Curve> supportedEllipticCurves();


    /**
     * Returns the elliptic curve of the key (JWK designation).
     *
     * @return The elliptic curve.
     */
    public Curve getCurve() {

        return curve;
    }

    /**
     * Encrypts the specified plaintext using the specified shared secret
     * ("Z").
     */
    protected JWECryptoParts encryptWithZ(JWEHeader header, SecretKey Z, byte[] clearText) {

        return encryptWithZ(header, Z, clearText, null);
    }

    /**
     * Encrypts the specified plaintext using the specified shared secret
     * ("Z") and, if provided, the content encryption key (CEK).
     */
    protected JWECryptoParts encryptWithZ(JWEHeader header,
                                          SecretKey Z,
                                          byte[] clearText,
                                          SecretKey contentEncryptionKey) {

        JWEAlgorithm alg = header.getAlgorithm();
        ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);
        EncryptionMethod enc = header.getEncryptionMethod();

        // Derive shared key via concat KDF
        SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

        SecretKey cek;
        Base64URLValue encryptedKey; // The CEK encrypted (second JWE part)

        if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
            cek = sharedKey;
            encryptedKey = null;
        } else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
            if (contentEncryptionKey != null) { // Use externally supplied CEK
                cek = contentEncryptionKey;
            } else { // Generate the CEK according to the enc method
                cek = ContentCryptoProvider.generateCEK(enc);
            }
            encryptedKey = Base64URLValue.encode(AESKW.wrapCEK(cek, sharedKey));
        } else {
            throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
        }

        return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey);
    }


    /**
     * Decrypts the encrypted JWE parts using the specified shared secret ("Z").
     */
    protected byte[] decryptWithZ(JWEHeader header,
                                  SecretKey Z,
                                  Base64URLValue encryptedKey,
                                  Base64URLValue iv,
                                  Base64URLValue cipherText,
                                  Base64URLValue authTag) {

        JWEAlgorithm alg = header.getAlgorithm();
        ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);

        // Derive shared key via concat KDF
        SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

        SecretKey cek;

        if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
            cek = sharedKey;
        } else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
            if (encryptedKey == null) {
                throw new JOSEException("Missing JWE encrypted key");
            }
            cek = AESKW.unwrapCEK(sharedKey, encryptedKey.decode());
        } else {
            throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
        }

        return ContentCryptoProvider.decrypt(header, iv, cipherText, authTag, cek);
    }


}
