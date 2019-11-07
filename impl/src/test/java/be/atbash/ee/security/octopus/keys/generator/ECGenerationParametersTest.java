/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ECGenerationParametersTest {

    @Test
    public void ecGenerationParameters() {
        ECGenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .withCurveName("secp256r1")
                .build();

        assertThat(parameters).isNotNull();
        assertThat(parameters.getKid()).isEqualTo("kid");
        assertThat(parameters.getKeyType()).isEqualTo(KeyType.EC);
        assertThat(parameters.getCurveName()).isEqualTo("secp256r1");

    }

    @Test(expected = KeyGenerationParameterException.class)
    public void ecGenerationParameters_invalidCurve() {
         new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .withCurveName("secp256x1")
                .build();

    }

    @Test(expected = KeyGenerationParameterException.class)
    public void ecGenerationParameters_kidRequired() {
        new ECGenerationParameters.ECGenerationParametersBuilder()
                .withCurveName("secp256r1")
                .build();

    }

    @Test(expected = KeyGenerationParameterException.class)
    public void ecGenerationParameters_curveRequired() {
        new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .build();

    }


}