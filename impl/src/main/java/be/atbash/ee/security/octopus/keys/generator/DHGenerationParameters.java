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

import javax.crypto.spec.DHParameterSpec;

@PublicAPI
public class DHGenerationParameters extends GenerationParameters {

    public static final KeyType DH = new KeyType("DH");

    private final int keySize;  // in bits
    private final DHParameterSpec parameterSpec; // or the Parameters to use for generation

    private DHGenerationParameters(DHGenerationParametersBuilder builder) {
        super(builder, DH);
        keySize = builder.keySize;
        parameterSpec = builder.parameterSpec;
    }

    public int getKeySize() {
        return keySize;
    }

    public DHParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    public static class DHGenerationParametersBuilder extends GenerationParametersBuilders<DHGenerationParametersBuilder> {

        private int keySize;
        private DHParameterSpec parameterSpec;

        public DHGenerationParameters build() {
            applyDefaults();
            return new DHGenerationParameters(this);
        }

        public DHGenerationParametersBuilder withKeySize(int keySize) {
            this.keySize = keySize;
            return this;
        }

        public DHGenerationParametersBuilder withDHParamaterSpec(DHParameterSpec dhParameterSpec) {
            parameterSpec = dhParameterSpec;
            return this;
        }

        @Override
        protected void applyDefaults() {
            super.applyDefaults();
            if (keySize == 0 && parameterSpec == null) {
                keySize = 2048;
            }
        }
    }
}
