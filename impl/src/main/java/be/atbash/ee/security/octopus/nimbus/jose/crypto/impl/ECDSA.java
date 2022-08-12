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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECParameterTable;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.util.Set;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) functions and utilities.
 * <p>
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
        i = rLength;
        while ((i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0)) {
            i--;
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j;
        j = sLength;
        while ((j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0)) {
            j--;
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

        try {
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
        } catch (Exception e) {
            // Watch for unchecked exceptions

            if (e instanceof JOSEException) {
                throw e;
            }

            throw new JOSEException(e.getMessage(), e);
        }
    }

    /**
     * Ensures the specified ECDSA signature is legal. Intended to prevent
     * attacks on JCA implementations vulnerable to CVE-2022-21449 and
     * similar bugs.
     *
     * @param jwsSignature The JWS signature. Must not be {@code null}.
     * @param jwsAlg       The ECDSA JWS algorithm. Must not be
     *                     {@code null}.
     * @throws JOSEException If the signature is found to be illegal, or
     *                       the JWS algorithm or curve are not supported.
     */
    public static void ensureLegalSignature(byte[] jwsSignature,
                                            JWSAlgorithm jwsAlg)
            throws JOSEException {

        if (ByteUtils.isZeroFilled(jwsSignature)) {
            // Quick check to make sure S and R are not both zero (CVE-2022-21449)
            throw new JOSEException("Blank signature");
        }

        Set<Curve> matchingCurves = Curve.forJWSAlgorithm(jwsAlg);
        if (matchingCurves.size() != 1) {
            throw new JOSEException("Unsupported JWS algorithm: " + jwsAlg);
        }

        Curve curve = matchingCurves.iterator().next();

        ECParameterSpec ecParameterSpec = ECParameterTable.get(curve);

        if (ecParameterSpec == null) {
            throw new JOSEException("Unsupported curve: " + curve);
        }

        int signatureLength = ECDSA.getSignatureByteArrayLength(jwsAlg);

        if (ECDSA.getSignatureByteArrayLength(jwsAlg) != jwsSignature.length) {
            // Quick format check, concatenation of R|S (may be padded
            // to match lengths) in ESxxx signatures has fixed length
            throw new JOSEException("Illegal signature length");
        }

        // Split the signature bytes in the middle
        int valueLength = signatureLength / 2;

        // Extract R
        byte[] rBytes = ByteUtils.subArray(jwsSignature, 0, valueLength);
        BigInteger rValue = new BigInteger(1, rBytes);

        // Extract S
        byte[] sBytes = ByteUtils.subArray(jwsSignature, valueLength, valueLength);
        BigInteger sValue = new BigInteger(1, sBytes);

        // Trivial zero check
        if (sValue.equals(BigInteger.ZERO) || rValue.equals(BigInteger.ZERO)) {
            throw new JOSEException("S and R must not be 0");
        }

        BigInteger N = ecParameterSpec.getOrder();

        // R and S must not be greater than the curve order N
        if (N.compareTo(rValue) < 1 || N.compareTo(sValue) < 1) {
            throw new JOSEException("S and R must not exceed N");
        }

        // Extra paranoid check
        if (rValue.mod(N).equals(BigInteger.ZERO) || sValue.mod(N).equals(BigInteger.ZERO)) {
            throw new JOSEException("R or S mod N != 0 check failed");
        }

        // Signature deemed legal, can proceed to DER transcoding and verification now
    }

    /**
     * Prevents public instantiation.
     */
    private ECDSA() {
    }
}
