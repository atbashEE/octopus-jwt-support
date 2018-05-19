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

import be.atbash.config.util.ResourceUtils;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.util.CollectionUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.KeyUse;

import java.security.Key;
import java.util.Arrays;
import java.util.List;

// Useful info https://www.cem.me/pki/
public class AtbashKey {

    private String keyId;
    private List<KeyUse> keyUses;
    private SecretKeyType secretKeyType;
    private Key key;

    public AtbashKey(String path, Key key) {
        this(path, Arrays.asList(KeyUse.ENCRYPTION, KeyUse.SIGNATURE), key);
    }

    public AtbashKey(String path, List<KeyUse> keyUses, Key key) {
        this.keyId = defineKeyId(path);
        this.keyUses = keyUses;
        if (CollectionUtils.isEmpty(this.keyUses)) {
            this.keyUses = Arrays.asList(KeyUse.ENCRYPTION, KeyUse.SIGNATURE);
        }
        this.key = key;
        secretKeyType = SecretKeyType.fromKey(key);
    }

    public String getKeyId() {
        return keyId;
    }

    public List<KeyUse> getKeyUses() {
        return keyUses;
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
        if (value.startsWith(ResourceUtils.CLASSPATH_PREFIX)) {
            int prefixStart = result.lastIndexOf('.');
            if (prefixStart != -1) {
                result = result.substring(0, prefixStart);
            }
            result = result.substring(ResourceUtils.CLASSPATH_PREFIX.length());
        }
        // FIXME Other prefixes.
        return result;
    }
}
