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

import com.nimbusds.jose.jwk.KeyType;

public class RSAGenerationParameters extends GenerationParameters {

    private int keySize;  // in bits

    private RSAGenerationParameters(RSAGenerationParametersBuilder builder) {
        super(builder, KeyType.RSA);
        keySize = builder.keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    public static class RSAGenerationParametersBuilder extends GenerationParametersBuilders<RSAGenerationParametersBuilder> {

        private int keySize;

        public RSAGenerationParameters build() {
            applyDefaults();
            return new RSAGenerationParameters(this);
        }

        public RSAGenerationParametersBuilder withKeySize(int keySize) {
            this.keySize = keySize;
            return this;
        }

        protected void applyDefaults() {
            super.applyDefaults();
            if (keySize == 0) {
                keySize = 2048;
            }
        }
    }
}
