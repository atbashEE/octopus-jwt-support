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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;

import java.util.Map;

/**
 *
 */

public class JWTParametersSigning implements JWTParameters {

    private Map<String, Object> headerValues;
    private KeyType keyType;
    private JWK secretKeySigning;

    public JWTParametersSigning(Map<String, Object> headerValues, KeyType keyType, JWK secretKeySigning) {

        this.headerValues = headerValues;
        this.keyType = keyType;
        this.secretKeySigning = secretKeySigning;
    }

    @Override
    public JWTEncoding getEncoding() {
        return JWTEncoding.JWS;
    }

    public Map<String, Object> getHeaderValues() {
        return headerValues;
    }

    public String getKeyID() {

        return secretKeySigning.getKeyID();

    }

    public KeyType getKeyType() {
        return keyType;
    }

    public JWK getJWK() {
        return secretKeySigning;
    }
}
