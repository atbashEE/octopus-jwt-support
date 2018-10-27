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
package be.atbash.ee.security.octopus.keys.generator;

import be.atbash.util.CollectionUtils;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;

import java.util.Arrays;
import java.util.List;

public class GenerationParameters {

    private String kid;
    private List<KeyUse> keyUsage;
    private KeyType keyType;

    GenerationParameters(GenerationParametersBuilders builder, KeyType keyType) {
        this.keyType = keyType;
        if (StringUtils.isEmpty(builder.kid)) {
            throw new KeyGenerationParameterException("Key id is required");
        }
        if (CollectionUtils.isEmpty(builder.keyUsage)) {
            throw new KeyGenerationParameterException("KeyUse information is required");
        }
        this.kid = builder.kid;
        this.keyUsage = builder.keyUsage;
    }

    public String getKid() {
        return kid;
    }

    public List<KeyUse> getKeyUsage() {
        return keyUsage;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    static class GenerationParametersBuilders<T extends GenerationParametersBuilders<T>> {
        private String kid;
        private List<KeyUse> keyUsage;

        public T withKeyId(String kid) {
            this.kid = kid;
            return (T) this;
        }

        protected void applyDefaults() {
            if (CollectionUtils.isEmpty(keyUsage)) {
                keyUsage = Arrays.asList(KeyUse.ENCRYPTION, KeyUse.SIGNATURE);
            }
        }
    }

}