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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.PublicAPI;

import java.security.Key;
import java.util.Map;

/**
 *
 */
@PublicAPI
public class JWTParametersSigning extends JWTParametersHeader {

    private AtbashKey secretKeySigning;

    public JWTParametersSigning(Map<String, Object> headerValues, AtbashKey secretKeySigning) {
        super(headerValues);
        this.secretKeySigning = secretKeySigning;
    }

    @Override
    public JWTEncoding getEncoding() {
        return JWTEncoding.JWS;
    }

    public String getKeyID() {

        return secretKeySigning.getKeyId();

    }

    public KeyType getKeyType() {
        return secretKeySigning.getSecretKeyType().getKeyType();
    }

    public Key getKey() {
        return secretKeySigning.getKey();
    }
}
