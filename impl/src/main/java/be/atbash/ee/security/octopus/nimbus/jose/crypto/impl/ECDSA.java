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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) functions and utilities.
 *
 * Based on code by Vladimir Dzhuvinov and Aleksei Doroganov
 */
public final class ECDSA {


    /**
     * Creates a new JCA signer / verifier for ECDSA.
     *
     * @param alg The ECDSA JWS algorithm. Must not be
     *            {@code null}.
     * @return The JCA signer / verifier instance.
     */
    public static Signature getSignerAndVerifier(JWSAlgorithm alg) {

        String jcaAlg;

        if (alg.equals(JWSAlgorithm.ES256)) {
            jcaAlg = "SHA256withECDSA";
        } else if (alg.equals(JWSAlgorithm.ES256K)) {
            jcaAlg = "SHA256withECDSA";
        } else if (alg.equals(JWSAlgorithm.ES384)) {
            jcaAlg = "SHA384withECDSA";
        } else if (alg.equals(JWSAlgorithm.ES512)) {
            jcaAlg = "SHA512withECDSA";
        } else {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWSAlgorithm(
                            alg,
                            ECDSAProvider.SUPPORTED_ALGORITHMS));
        }

        try {
            return Signature.getInstance(jcaAlg, BouncyCastleProviderSingleton.getInstance());

        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Unsupported ECDSA algorithm: " + e.getMessage(), e);
        }
    }


    /**
     * Returns the expected signature byte array length (R + S parts) for
     * the specified ECDSA algorithm.
     *
     * @param alg The ECDSA algorithm. Must be supported and not
     *            {@code null}.
     * @return The expected byte array length for the signature.
     */
    public static int getSignatureByteArrayLength(JWSAlgorithm alg) {

        if (alg.equals(JWSAlgorithm.ES256)) {

            return 64;

        } else if (alg.equals(JWSAlgorithm.ES256K)) {

            return 64;

        } else if (alg.equals(JWSAlgorithm.ES384)) {

            return 96;

        } else if (alg.equals(JWSAlgorithm.ES512)) {

            return 132;

        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
                    alg,
                    ECDSAProvider.SUPPORTED_ALGORITHMS));
        }
    }


    /**
     * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
     * R + S format expected by ECDSA JWS.
     *
     * @param derSignature The ASN1./DER-encoded. Must not be {@code null}.
     * @param outputLength The expected length of the ECDSA JWS signature.
     * @return The ECDSA JWS encoded signature.
     */
    public static byte[] transcodeSignatureToConcat(byte[] derSignature, int outputLength) {

        if (derSignature.length < 8 || derSignature[0] != 48) {
            throw new JOSEException("Invalid ECDSA signature format");
        }

        int offset;
        if (derSignature[1] > 0) {
            offset = 2;
        } else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new JOSEException("Invalid ECDSA signature format");
        }

        byte rLength = derSignature[offset + 1];

        int i;
        for (i = rLength; (i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0); i--) {
            // do nothing
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j;
        for (j = sLength; (j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--) {
            // do nothing
        }

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength / 2);

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
                || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derSignature[offset] != 2
                || derSignature[offset + 2 + rLength] != 2) {
            throw new JOSEException("Invalid ECDSA signature format");
        }

        byte[] concatSignature = new byte[2 * rawLen];

        System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
        System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

        return concatSignature;
    }


    /**
     * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
     * the JCA verifier.
     *
     * @param jwsSignature The JWS signature, consisting of the
     *                     concatenated R and S values. Must not be
     *                     {@code null}.
     * @return The ASN.1/DER encoded signature.
     */
    public static byte[] transcodeSignatureToDER(byte[] jwsSignature) {

        // Adapted from org.apache.xml.security.algorithms.implementations.SignatureECDSA

        int rawLen = jwsSignature.length / 2;

        int i;

        for (i = rawLen; (i > 0) && (jwsSignature[rawLen - i] == 0); i--) {
            // do nothing
        }

        int j = i;

        if (jwsSignature[rawLen - i] < 0) {
            j += 1;
        }

        int k;

        for (k = rawLen; (k > 0) && (jwsSignature[2 * rawLen - k] == 0); k--) {
            // do nothing
        }

        int l = k;

        if (jwsSignature[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;

        if (len > 255) {
            throw new JOSEException("Invalid ECDSA signature format");
        }

        int offset;

        byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }


    /**
     * Prevents public instantiation.
     */
    private ECDSA() {
    }
}
