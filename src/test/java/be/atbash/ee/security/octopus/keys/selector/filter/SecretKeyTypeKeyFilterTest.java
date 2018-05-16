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
package be.atbash.ee.security.octopus.keys.selector.filter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.util.exception.AtbashIllegalActionException;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class SecretKeyTypeKeyFilterTest {

    private static AtbashKey key1;
    private static AtbashKey key2;

    private SecretKeyTypeKeyFilter keyFilter;

    @BeforeClass
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

        assertThat(data).hasSize(1);
        assertThat(data.get(0)).isEqualTo(key1);

    }

    @Test
    public void filter_NoMatch() {
        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC);
        keyFilter = new SecretKeyTypeKeyFilter(secretKeyType);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).isEmpty();

    }

    @Test(expected = AtbashIllegalActionException.class)
    public void filter_NullArgument() {
        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC);
        keyFilter = new SecretKeyTypeKeyFilter(secretKeyType);
        keyFilter.filter(null);

    }

    @Test(expected = AtbashIllegalActionException.class)
    public void filter_NullSecretKeyType() {
        keyFilter = new SecretKeyTypeKeyFilter(null);

    }

}