/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static be.atbash.ee.security.octopus.keys.generator.DHGenerationParameters.DH;
import static org.assertj.core.api.Assertions.assertThat;

public class DHGenerationParametersTest {

    @Test
    public void dhGenerationParameters() {
        DHGenerationParameters parameters = new DHGenerationParameters.DHGenerationParametersBuilder()
                .withKeyId("kid")
                .withKeySize(124)
                .build();

        assertThat(parameters).isNotNull();
        assertThat(parameters.getKid()).isEqualTo("kid");
        assertThat(parameters.getKeyType()).isEqualTo(DH);
        assertThat(parameters.getKeySize()).isEqualTo(124);

    }

    @Test
    public void dhGenerationParameters_kidRequired() {
        Assertions.assertThrows(KeyGenerationParameterException.class, () ->
                new DHGenerationParameters.DHGenerationParametersBuilder()
                        .withKeySize(124)
                        .build()
        );
    }


    @Test
    public void dhGenerationParameters_defaultSize() {
        DHGenerationParameters parameters = new DHGenerationParameters.DHGenerationParametersBuilder()
                .withKeyId("kid")
                .build();

        assertThat(parameters).isNotNull();
        assertThat(parameters.getKid()).isEqualTo("kid");
        assertThat(parameters.getKeyType()).isEqualTo(DH);
        assertThat(parameters.getKeySize()).isEqualTo(2048);

    }

}