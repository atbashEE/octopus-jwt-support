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

@PublicAPI
public class OCTGenerationParameters extends GenerationParameters {

    private final int keySize;  // in bits

    private OCTGenerationParameters(OCTGenerationParametersBuilder builder) {
        super(builder, KeyType.OCT);
        keySize = builder.keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    public static class OCTGenerationParametersBuilder extends GenerationParametersBuilders<OCTGenerationParametersBuilder> {

        private int keySize;

        public OCTGenerationParameters build() {
            applyDefaults();
            return new OCTGenerationParameters(this);
        }

        public OCTGenerationParameters.OCTGenerationParametersBuilder withKeySize(int keySize) {
            this.keySize = keySize;
            return this;
        }

        @Override
        protected void applyDefaults() {
            super.applyDefaults();
            if (keySize == 0) {
                keySize = 256;
            }
        }
    }
}
