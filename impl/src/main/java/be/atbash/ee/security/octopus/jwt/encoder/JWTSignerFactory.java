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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.UnsupportedKeyType;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.exception.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.KeyType;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 *
 */
@ApplicationScoped
public class JWTSignerFactory {

    @Inject
    private HMACAlgorithmFactory hmacAlgorithmFactory;

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    public JWSSigner createSigner(JWTParametersSigning parametersSigning) {
        JWSSigner result = null;

        if (KeyType.OCT.equals(parametersSigning.getKeyType())) {
            try {
                result = new MACSigner(parametersSigning.getKey().getEncoded());
            } catch (KeyLengthException e) {

                throw new AtbashUnexpectedException(e);
                // TODO
                //This should be already covered by HMACAlgorithmFactory.
                // What when developers are using this directly?
            }
        }
        if (KeyType.RSA.equals(parametersSigning.getKeyType())) {
            if (parametersSigning.getKey() instanceof PrivateKey) {
                result = new RSASSASigner((PrivateKey) parametersSigning.getKey());
            } else {
                throw new UnsupportedKeyType(AsymmetricPart.PRIVATE, "JWS Signing");
            }
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {

            if (parametersSigning.getKey() instanceof ECPrivateKey) {
                try {
                    result = new ECDSASigner((ECPrivateKey) parametersSigning.getKey());
                } catch (JOSEException e) {
                    throw new UnsupportedECCurveException(e.getMessage());
                }
            } else {
                throw new UnsupportedKeyType(AsymmetricPart.PRIVATE, "JWS Signing");
            }
        }

        if (result == null) {
            throw new UnsupportedKeyType(parametersSigning.getKeyType(), "JWT Signing");
        }
        return result;
    }

    public JWSAlgorithm defineJWSAlgorithm(JWTParametersSigning parametersSigning) {
        checkDependencies();

        JWSAlgorithm result = null;

        if (KeyType.OCT.equals(parametersSigning.getKeyType())) {

            result = hmacAlgorithmFactory.determineOptimalAlgorithm(parametersSigning.getKey().getEncoded());
        }
        if (KeyType.RSA.equals(parametersSigning.getKeyType())) {

            result = jwtSupportConfiguration.getJWSAlgorithmForRSA();
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {

            try {
                result = resolveAlgorithm((ECKey) parametersSigning.getKey());
            } catch (JOSEException e) {
                throw new UnsupportedECCurveException(e.getMessage());
            }
        }
        if (result == null) {
            throw new UnsupportedKeyType(parametersSigning.getKeyType(), "JWT Signing");
        }

        return result;
    }

    /* Copied from com.nimbusds.jose.crypto.ECDSA which has package scope */
    private JWSAlgorithm resolveAlgorithm(final ECKey ecKey)
            throws JOSEException {

        ECParameterSpec ecParameterSpec = ecKey.getParams();
        return resolveAlgorithm(Curve.forECParameterSpec(ecParameterSpec));
    }

    private JWSAlgorithm resolveAlgorithm(final Curve curve)
            throws JOSEException {

        if (curve == null) {
            throw new JOSEException("The EC key curve is not supported, must be P-256, P-384 or P-521");
        } else if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        } else if (Curve.P_256K.equals(curve)) {
            return JWSAlgorithm.ES256K;
        } else if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        } else if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        } else {
            throw new JOSEException("Unexpected curve: " + curve);
        }
    }

    private void checkDependencies() {
        // We have CDI injected dependencies, but in a Java SE environment it is possible that they are empty.
        if (hmacAlgorithmFactory == null) {
            hmacAlgorithmFactory = new HMACAlgorithmFactory();
        }

        if (jwtSupportConfiguration == null) {
            jwtSupportConfiguration = JwtSupportConfiguration.getInstance();
        }
    }

}
