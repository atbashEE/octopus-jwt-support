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

import be.atbash.ee.security.octopus.exception.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.exception.UnsupportedKeyLengthException;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.AESEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDHEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.PasswordBasedEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSAEncrypter;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEEncrypter;

import javax.crypto.SecretKey;
import javax.enterprise.context.ApplicationScoped;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

@ApplicationScoped
public class JWEEncryptionFactory {

    private static final String JWE_CREATION = "JWE creation";

    public JWEEncrypter createEncryptor(JWTParametersEncryption parametersEncryption) {
        JWEEncrypter result = null;

        if (KeyType.RSA.equals(parametersEncryption.getKeyType())) {

            if (parametersEncryption.getKey() instanceof RSAPublicKey) {
                result = new RSAEncrypter((RSAPublicKey) parametersEncryption.getKey());
            } else {
                throw new KeyTypeException(AsymmetricPart.PUBLIC, JWE_CREATION);
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
                throw new KeyTypeException(AsymmetricPart.PUBLIC, JWE_CREATION);
            }
        }

        if (KeyType.OCT.equals(parametersEncryption.getKeyType())) {
            if (parametersEncryption.getHeaderValues().containsKey("p2s")) {
                result = new PasswordBasedEncrypter((SecretKey) parametersEncryption.getKey());
            } else {
                try {
                    result = new AESEncrypter((SecretKey) parametersEncryption.getKey());
                } catch (KeyLengthException e) {
                    throw new UnsupportedKeyLengthException("Unsupported Key length");
                }
            }
        }
        if (result == null) {
            throw new KeyTypeException(parametersEncryption.getKeyType(), JWE_CREATION);
        }
        return result;

    }
}
