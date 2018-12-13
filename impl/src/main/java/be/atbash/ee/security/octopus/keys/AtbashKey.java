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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.json.AtbashKeyCustomBeanJSONEncoder;
import be.atbash.ee.security.octopus.keys.json.AtbashKeyWriter;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.json.parser.MappedBy;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

import java.security.Key;

// Useful info https://www.cem.me/pki/
@MappedBy(writer = AtbashKeyWriter.class, beanEncoder = AtbashKeyCustomBeanJSONEncoder.class)
public class AtbashKey {

    private String keyId;
    private SecretKeyType secretKeyType;
    private Key key;

    public AtbashKey(String path, Key key) {

        // FIXME Check key is not null
        this.keyId = defineKeyId(path);
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

    private String defineKeyId(String value) {
        if (value == null) {
            throw new AtbashUnexpectedException("Parameter cannot be null");
        }
        String result = value;
        if (value.startsWith(ResourceUtil.CLASSPATH_PREFIX)) {
            int prefixStart = result.lastIndexOf('.');
            if (prefixStart != -1) {
                result = result.substring(0, prefixStart);
            }
            result = result.substring(ResourceUtil.CLASSPATH_PREFIX.length());
        }
        // FIXME Other prefixes.
        return result;
    }

    public boolean isMatch(String keyId, AsymmetricPart asymmetricPart) {
        return this.keyId.equals(keyId) && secretKeyType.getAsymmetricPart() == asymmetricPart;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
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
