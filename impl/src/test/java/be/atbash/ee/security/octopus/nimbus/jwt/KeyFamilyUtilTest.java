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
package be.atbash.ee.security.octopus.nimbus.jwt;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.*;
import be.atbash.ee.security.octopus.nimbus.KeyFamily;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class KeyFamilyUtilTest {

    @Test
    void determineKeyFamily_rsa() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .withKeySize(2048)
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        // Some basic check
        Assertions.assertThat(keys).hasSize(2);

        KeyFamily keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(0).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.RSA_PUBLIC);

        keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(1).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.RSA_PRIVATE);

    }

    @Test
    void determineKeyFamily_ec() {
        ECGenerationParameters generationParameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("kid")
                .withCurveName("secp256r1")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        // Some basic check
        Assertions.assertThat(keys).hasSize(2);

        KeyFamily keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(0).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.EC_PUBLIC);

        keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(1).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.EC_PRIVATE);

    }

    @Test
    void determineKeyFamily_okp() {
        OKPGenerationParameters generationParameters = new OKPGenerationParameters.OKPGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        // Some basic check
        Assertions.assertThat(keys).hasSize(2);

        KeyFamily keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(0).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.OKP_PUBlIC);

        keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(1).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.OKP_PRIVATE);

    }

    @Test
    void determineKeyFamily_oct() {
        OCTGenerationParameters generationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        // Some basic check
        Assertions.assertThat(keys).hasSize(1);

        KeyFamily keyFamily = KeyFamilyUtil.INSTANCE.determineKeyFamily(keys.get(0).getKey());
        Assertions.assertThat(keyFamily).isEqualTo(KeyFamily.AES);


    }
}