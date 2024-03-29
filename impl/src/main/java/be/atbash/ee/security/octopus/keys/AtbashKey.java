/*
 * Copyright 2017-2022 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.PublicAPI;
import be.atbash.util.resource.ResourceUtil;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

// Useful info https://www.cem.me/pki/
@PublicAPI
public class AtbashKey {

    private final String keyId;
    private final SecretKeyType secretKeyType;
    private final Key key;

    /**
     * Creates an AtbashKey from the cryptographic key and the Key id. When the key Id starts with a classpath,
     * File or URL prefix, the kid is based on the 'resource' name.
     *
     * @param kid The identification
     * @param key The cryptographic key
     */
    public AtbashKey(String kid, Key key) {

        if (key == null) {
            throw new IllegalArgumentException("Parameter key cannot be null");
        }
        if (kid == null) {
            throw new IllegalArgumentException("Parameter kid cannot be null");
        }

        keyId = defineKeyId(kid);
        this.key = key;
        secretKeyType = SecretKeyType.fromKey(key);
    }

    public String getKeyId() {
        return keyId;
    }

    public SecretKeyType getSecretKeyType() {
        return secretKeyType;
    }

    public Key getKey() {
        return key;
    }

    public String getSpecification() {
        StringBuilder result = new StringBuilder();
        if (KeyType.EC.equals(secretKeyType.getKeyType())) {
            Curve curve = ECCurveHelper.getCurve((ECKey) key);
            result.append("Curve name : ").append(curve == null ? "unknown" : curve.getName());
        }
        if (KeyType.RSA.equals(secretKeyType.getKeyType())) {
            RSAKey rsaKey = (RSAKey) key;
            result.append("key length : ").append(rsaKey.getModulus().bitLength());
        }
        if (KeyType.OCT.equals(secretKeyType.getKeyType())) {
            result.append("key length : ").append(key.getEncoded().length * 8);
        }
        if (KeyType.OKP.equals(secretKeyType.getKeyType())) {
            result.append("Curve name : Ed25519");  // TODO Support for other EdDSA algorithms.
        }
        return result.toString();
    }

    private String defineKeyId(String value) {
        String result = value;
        if (value.startsWith(ResourceUtil.CLASSPATH_PREFIX)) {
            result = defineKeyId(result, ResourceUtil.CLASSPATH_PREFIX);
        }
        if (value.startsWith(ResourceUtil.FILE_PREFIX)) {
            result = defineKeyId(result, ResourceUtil.FILE_PREFIX);
        }
        if (value.startsWith(ResourceUtil.URL_PREFIX)) {
            try {
                result = result.substring(ResourceUtil.URL_PREFIX.length());
                URL url = new URL(result);
                result = defineKeyId(url.getPath(), "");
            } catch (MalformedURLException e) {
                // Use de value without prefix as key
            }
        }
        return result;
    }

    private String defineKeyId(String result, String prefix) {
        int prefixStart = result.lastIndexOf('.');
        if (prefixStart != -1) {
            result = result.substring(0, prefixStart);
        }
        result = result.substring(prefix.length());
        return result;
    }

    public boolean isMatch(String keyId, AsymmetricPart asymmetricPart) {
        return this.keyId.equals(keyId) && secretKeyType.getAsymmetricPart() == asymmetricPart;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        AtbashKey atbashKey = (AtbashKey) o;

        if (!keyId.equals(atbashKey.keyId)) {
            return false;
        }
        return secretKeyType.equals(atbashKey.secretKeyType);
    }

    @Override
    public int hashCode() {
        int result = keyId.hashCode();
        result = 31 * result + secretKeyType.hashCode();
        return result;
    }

    public static class AtbashKeyBuilder {
        private String keyId;
        private Key key;

        public AtbashKeyBuilder withKeyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public AtbashKeyBuilder withKey(Key key) {
            this.key = key;
            return this;
        }

        public AtbashKey build() {
            return new AtbashKey(keyId, key);
        }
    }
}
