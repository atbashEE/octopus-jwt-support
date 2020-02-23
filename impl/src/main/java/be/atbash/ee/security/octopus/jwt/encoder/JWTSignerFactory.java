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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.Ed25519Signer;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ECUtils;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.interfaces.ECKey;

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

            result = new MACSigner(parametersSigning.getAtbashKey());

        }
        if (KeyType.RSA.equals(parametersSigning.getKeyType())) {
                result = new RSASSASigner(parametersSigning.getAtbashKey());
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {

                result = new ECDSASigner(parametersSigning.getAtbashKey());
        }

        if (KeyType.OKP.equals(parametersSigning.getKeyType())) {

                result = new Ed25519Signer(parametersSigning.getAtbashKey());
        }

        if (result == null) {
            throw new KeyTypeException(parametersSigning.getKeyType(), "JWT Signing");
        }
        return result;
    }

    public JWSAlgorithm defineJWSAlgorithm(JWTParametersSigning parametersSigning) {
        checkDependencies();

        JWSAlgorithm result = null;

        if (KeyType.OCT.equals(parametersSigning.getKeyType())) {

            result = hmacAlgorithmFactory.determineOptimalAlgorithm(parametersSigning.getKey().getEncoded());
        }
        if (KeyType.OKP.equals(parametersSigning.getKeyType())) {

            result = JWSAlgorithm.EdDSA;
        }
        if (KeyType.RSA.equals(parametersSigning.getKeyType())) {

            result = jwtSupportConfiguration.getJWSAlgorithmForRSA();
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {

            result = ECUtils.resolveAlgorithm((ECKey) parametersSigning.getKey());
        }
        if (result == null) {
            throw new KeyTypeException(parametersSigning.getKeyType(), "JWT Signing");
        }

        return result;
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
