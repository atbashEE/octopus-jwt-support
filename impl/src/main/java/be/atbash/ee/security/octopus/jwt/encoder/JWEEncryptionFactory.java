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
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.KeyType;

import javax.enterprise.context.ApplicationScoped;
import java.security.interfaces.RSAPublicKey;

@ApplicationScoped
public class JWEEncryptionFactory {

    public JWEEncrypter createEncryptor(JWTParametersEncryption parametersEncryption) {
        JWEEncrypter result = null;

        if (KeyType.RSA.equals(parametersEncryption.getKeyType())) {
            result = new RSAEncrypter((RSAPublicKey) parametersEncryption.getKey());
        }

        // FIXME EC and AES encryptor
        // Based on password ??
        if (result == null) {
            throw new UnsupportedKeyType(parametersEncryption.getKeyType(), "JWE creation");
        }
        return result;

    }
}
