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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import com.nimbusds.jose.jwk.KeyType;

import java.security.Key;
import java.util.Map;

/**
 *
 */

public class JWTParametersEncryption implements JWTParameters {

    private Map<String, Object> headerValues;
    private AtbashKey secretKeyEncryption;
    private JWTParametersSigning parametersSigning;

    public JWTParametersEncryption(JWTParametersSigning parametersSigning, Map<String, Object> headerValues, AtbashKey secretKeyEncryption) {
        this.parametersSigning = parametersSigning;

        this.headerValues = headerValues;
        this.secretKeyEncryption = secretKeyEncryption;
    }

    @Override
    public JWTEncoding getEncoding() {
        return JWTEncoding.JWE;
    }

    public Map<String, Object> getHeaderValues() {
        return headerValues;
    }

    public String getKeyID() {

        return secretKeyEncryption.getKeyId();

    }

    public Key getKey() {
        return secretKeyEncryption.getKey();
    }

    public KeyType getKeyType() {
        return secretKeyEncryption.getSecretKeyType().getKeyType();
    }

    public JWTParametersSigning getParametersSigning() {
        return parametersSigning;
    }

}