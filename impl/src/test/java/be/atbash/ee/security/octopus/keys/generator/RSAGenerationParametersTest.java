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
import org.junit.jupiter.api.Test;

import org.assertj.core.api.Assertions;

public class RSAGenerationParametersTest {

    @Test
    public void rsaGenerationParameters() {
        RSAGenerationParameters parameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .withKeySize(124)
                .build();

        Assertions.assertThat(parameters).isNotNull();
        Assertions.assertThat(parameters.getKid()).isEqualTo("kid");
        Assertions.assertThat(parameters.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(parameters.getKeySize()).isEqualTo(124);

    }

    @Test
    public void rsaGenerationParameters_kidRequired() {
        Assertions.assertThatThrownBy(() -> new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeySize(124)
                .build()
        ).isInstanceOf(KeyGenerationParameterException.class);
    }

    @Test
    public void rsaGenerationParameters_defaultSize() {
        RSAGenerationParameters parameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .build();

        Assertions.assertThat(parameters).isNotNull();
        Assertions.assertThat(parameters.getKid()).isEqualTo("kid");
        Assertions.assertThat(parameters.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(parameters.getKeySize()).isEqualTo(2048);

    }
}