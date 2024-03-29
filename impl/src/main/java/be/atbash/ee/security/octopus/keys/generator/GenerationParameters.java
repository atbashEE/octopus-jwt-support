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
package be.atbash.ee.security.octopus.keys.generator;

import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;

@PublicAPI
public class GenerationParameters {

    private final String kid;
    private final KeyType keyType;

    GenerationParameters(GenerationParametersBuilders<?> builder, KeyType keyType) {
        this.keyType = keyType;
        if (StringUtils.isEmpty(builder.kid)) {
            throw new KeyGenerationParameterException("Key id is required");
        }
        kid = builder.kid;
    }

    public String getKid() {
        return kid;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    static class GenerationParametersBuilders<T extends GenerationParametersBuilders<T>> {
        private String kid;

        public T withKeyId(String kid) {
            this.kid = kid;
            return (T) this;
        }

        protected void applyDefaults() {
            // Default impl does nothing. Subclasses should override
        }
    }

}
