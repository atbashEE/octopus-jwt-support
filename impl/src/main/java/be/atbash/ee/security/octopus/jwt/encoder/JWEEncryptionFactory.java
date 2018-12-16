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

import be.atbash.ee.security.octopus.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.UnsupportedKeyType;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.KeyType;

import javax.crypto.SecretKey;
import javax.enterprise.context.ApplicationScoped;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

@ApplicationScoped
public class JWEEncryptionFactory {

    public JWEEncrypter createEncryptor(JWTParametersEncryption parametersEncryption) {
        JWEEncrypter result = null;

        if (KeyType.RSA.equals(parametersEncryption.getKeyType())) {

            if (parametersEncryption.getKey() instanceof RSAPublicKey) {
                result = new RSAEncrypter((RSAPublicKey) parametersEncryption.getKey());
            } else {
                throw new UnsupportedKeyType(AsymmetricPart.PUBLIC, "JWE creation");
            }
        }

        if (KeyType.EC.equals(parametersEncryption.getKeyType())) {
            if (parametersEncryption.getKey() instanceof ECPublicKey) {
                try {
                    result = new ECDHEncrypter((ECPublicKey) parametersEncryption.getKey());
                } catch (JOSEException e) {
                    // thrown by com.nimbusds.jose.crypto.ECDHCryptoProvider.ECDHCryptoProvider
                    // when EC Key with unsupported curve is found.
                    throw new UnsupportedECCurveException(e.getMessage());
                }
            } else {
                throw new UnsupportedKeyType(AsymmetricPart.PUBLIC, "JWE creation");
            }
        }

        if (KeyType.OCT.equals(parametersEncryption.getKeyType())) {
            try {
                result = new AESEncrypter((SecretKey) parametersEncryption.getKey());
            } catch (KeyLengthException e) {
                // FIXME
                e.printStackTrace();
            }
        }
        if (result == null) {
            throw new UnsupportedKeyType(parametersEncryption.getKeyType(), "JWE creation");
        }
        return result;

    }
}
