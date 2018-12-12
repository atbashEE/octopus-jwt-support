/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyType;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

/**
 *
 */
@ApplicationScoped
public class JWTSignerFactory {

    @Inject
    private HMACAlgorithmFactory hmacAlgorithmFactory;

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
            result = new RSASSASigner((PrivateKey) parametersSigning.getKey());
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {

            try {
                result = new ECDSASigner((ECPrivateKey) parametersSigning.getKey());
            } catch (JOSEException e) {
                throw new AtbashUnexpectedException(e);
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

            result = JWSAlgorithm.RS256; // FIXME Is this always (what about 384 and 512
        }
        if (KeyType.EC.equals(parametersSigning.getKeyType())) {
            result = JWSAlgorithm.ES256; // FIXME Is this always (what about 384 and 512
        }
        if (result == null) {
            throw new UnsupportedKeyType(parametersSigning.getKeyType(), "JWT Signing");
        }

        return result;
    }

    private void checkDependencies() {
        // We have CDI injected dependencies, but in a Java SE environment it is possible that they are empty.
        if (hmacAlgorithmFactory == null) {
            hmacAlgorithmFactory = new HMACAlgorithmFactory();
        }
    }

}
