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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

public class KeyGeneratorTest {

    private static final String KID = "kid";

    private KeyGenerator keyGenerator;

    @BeforeEach
    public void setup() {
        keyGenerator = new KeyGenerator();
    }

    @Test
    public void generateKeys_RSA() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(KID)
                .build();

        List<AtbashKey> keys = keyGenerator.generateKeys(generationParameters);

        Assertions.assertThat(keys).hasSize(2);
        for (int i = 0; i < 2; i++) {
            Assertions.assertThat(keys.get(i).getSecretKeyType().getKeyType()).isEqualTo(KeyType.RSA);
            Assertions.assertThat(keys.get(i).getKeyId()).isEqualTo(KID);
        }
    }

    @Test
    public void generateKeys_EC() {
        ECGenerationParameters generationParameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId(KID)
                .withCurveName("secp256r1")
                .build();

        List<AtbashKey> keys = keyGenerator.generateKeys(generationParameters);

        Assertions.assertThat(keys).hasSize(2);
        for (int i = 0; i < 2; i++) {
            Assertions.assertThat(keys.get(i).getSecretKeyType().getKeyType()).isEqualTo(KeyType.EC);
            Assertions.assertThat(keys.get(i).getKeyId()).isEqualTo(KID);
        }

    }

    @Test
    public void generateKeys_DH() {
        DHGenerationParameters generationParameters = new DHGenerationParameters.DHGenerationParametersBuilder()
                .withKeyId(KID)
                .build();

        List<AtbashKey> keys = keyGenerator.generateKeys(generationParameters);

        Assertions.assertThat(keys).hasSize(2);
        for (int i = 0; i < 2; i++) {
            Assertions.assertThat(keys.get(i).getSecretKeyType().getKeyType()).isEqualTo(DHGenerationParameters.DH);
            Assertions.assertThat(keys.get(i).getKeyId()).isEqualTo(KID);
        }
    }

    @Test
    public void generateKeys_OCT() {
        OCTGenerationParameters generationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeyId(KID)
                .build();

        List<AtbashKey> keys = keyGenerator.generateKeys(generationParameters);

        Assertions.assertThat(keys).hasSize(1);

        Assertions.assertThat(keys.get(0).getSecretKeyType().getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(keys.get(0).getKeyId()).isEqualTo(KID);

    }

    @Test
    public void generateKeys_OKP() {
        OKPGenerationParameters generationParameters = new OKPGenerationParameters.OKPGenerationParametersBuilder()
                .withKeyId(KID)
                .build();

        List<AtbashKey> keys = keyGenerator.generateKeys(generationParameters);

        Assertions.assertThat(keys).hasSize(2);
        for (int i = 0; i < 2; i++) {
            Assertions.assertThat(keys.get(i).getSecretKeyType().getKeyType()).isEqualTo(KeyType.OKP);
            Assertions.assertThat(keys.get(i).getKeyId()).isEqualTo(KID);
        }

    }
}