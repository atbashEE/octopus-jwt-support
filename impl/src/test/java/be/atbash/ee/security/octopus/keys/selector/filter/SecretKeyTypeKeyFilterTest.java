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
package be.atbash.ee.security.octopus.keys.selector.filter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class SecretKeyTypeKeyFilterTest {

    private static AtbashKey key1;
    private static AtbashKey key2;

    private SecretKeyTypeKeyFilter keyFilter;

    @BeforeAll
    public static void defineKeys() {
        KeyGenerator generator = new KeyGenerator();

        RSAGenerationParameters generationParameters1 = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("rsa")
                .build();
        List<AtbashKey> keys = generator.generateKeys(generationParameters1);

        key1 = keys.get(1); // We need the private key

        ECGenerationParameters generationParameters2 = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId("ec")
                .withCurveName("secp256r1")
                .build();
        keys = generator.generateKeys(generationParameters2);

        key2 = keys.get(1); // We need the private key
    }

    @Test
    public void filter() {
        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);
        keyFilter = new SecretKeyTypeKeyFilter(secretKeyType);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);

        List<AtbashKey> data = keyFilter.filter(keys);

        Assertions.assertThat(data).hasSize(1);
        Assertions.assertThat(data.get(0)).isEqualTo(key1);

    }

    @Test
    public void filter_NoMatch() {
        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC);
        keyFilter = new SecretKeyTypeKeyFilter(secretKeyType);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);

        List<AtbashKey> data = keyFilter.filter(keys);

        Assertions.assertThat(data).isEmpty();

    }

    @Test
    public void filter_NullArgument() {
        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC);
        keyFilter = new SecretKeyTypeKeyFilter(secretKeyType);
        Assertions.assertThatThrownBy(() -> keyFilter.filter(null))
                .isInstanceOf(AtbashIllegalActionException.class);

    }

    @Test
    public void filter_NullSecretKeyType() {
        Assertions.assertThatThrownBy(() -> keyFilter = new SecretKeyTypeKeyFilter(null))
                .isInstanceOf(AtbashIllegalActionException.class);

    }

}