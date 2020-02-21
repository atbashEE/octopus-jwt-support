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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;


/**
 * RSA-SSA functions and utilities.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class RSASSA {


    /**
     * Returns a signer and verifier for the specified RSASSA-based JSON
     * Web Algorithm (JWA).
     *
     * @param alg The JSON Web Algorithm (JWA). Must be supported and not
     *            {@code null}.
     * @return A signer and verifier instance.
     */
    public static Signature getSignerAndVerifier(JWSAlgorithm alg) {

        // The JCE crypto provider uses different alg names

        String jcaAlg;

        PSSParameterSpec pssSpec = null;

        if (alg.equals(JWSAlgorithm.RS256)) {
            jcaAlg = "SHA256withRSA";
        } else if (alg.equals(JWSAlgorithm.RS384)) {
            jcaAlg = "SHA384withRSA";
        } else if (alg.equals(JWSAlgorithm.RS512)) {
            jcaAlg = "SHA512withRSA";
        } else if (alg.equals(JWSAlgorithm.PS256)) {
            jcaAlg = "SHA256withRSAandMGF1";
            // JWA mandates salt length must equal hash
            pssSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        } else if (alg.equals(JWSAlgorithm.PS384)) {
            jcaAlg = "SHA384withRSAandMGF1";
            // JWA mandates salt length must equal hash
            pssSpec = new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
        } else if (alg.equals(JWSAlgorithm.PS512)) {
            jcaAlg = "SHA512withRSAandMGF1";
            // JWA mandates salt length must equal hash
            pssSpec = new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, RSASSAProvider.SUPPORTED_ALGORITHMS));
        }

        Signature signature;
        try {

            signature = Signature.getInstance(jcaAlg, BouncyCastleProviderSingleton.getInstance());

        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Unsupported RSASSA algorithm: " + e.getMessage(), e);
        }


        if (pssSpec != null) {
            try {
                signature.setParameter(pssSpec);
            } catch (InvalidAlgorithmParameterException e) {
                throw new JOSEException("Invalid RSASSA-PSS salt length parameter: " + e.getMessage(), e);
            }
        }

        return signature;
    }


    /**
     * Prevents public instantiation.
     */
    private RSASSA() {

    }
}
