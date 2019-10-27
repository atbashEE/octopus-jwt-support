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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.nimbus.jose.jwk.JWKSet;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */

public class KeyEncoderParameters {

    private char[] keyPassword;
    private char[] filePassword;
    private KeyStore keyStore;
    private JWKSet jwkSet;
    private Map<Object, Object> additionalValues;

    public KeyEncoderParameters() {
        additionalValues = new HashMap<>();
    }

    public KeyEncoderParameters(char[] keyPassword) {
        this();
        this.keyPassword = keyPassword;
    }

    public KeyEncoderParameters(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    public KeyEncoderParameters(char[] keyPassword, char[] filePassword, KeyStore keyStore) {
        this();
        this.keyPassword = keyPassword;
        this.filePassword = filePassword;
        this.keyStore = keyStore;
    }

    public void addValue(Class<?> keyClass, Object value) {
        additionalValues.put(keyClass, value);
    }

    public void addValue(String key, Object value) {
        additionalValues.put(key, value);
    }

    public char[] getKeyPassword() {
        return keyPassword;
    }

    public char[] getFilePassword() {
        return filePassword;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public JWKSet getJwkSet() {
        return jwkSet;
    }

    public <T> T getValue(Class<T> keyClass) {
        return (T) additionalValues.get(keyClass);
    }

    public <T> T getValue(String key, Class<T> valueClass) {
        return (T) additionalValues.get(key);
    }
}
