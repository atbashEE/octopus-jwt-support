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
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.OCTGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AsymmetricPartKeyFilterTest {

    private static AtbashKey key1;
    private static AtbashKey key2;
    private static AtbashKey key3;

    private AsymmetricPartKeyFilter keyFilter;

    @BeforeClass
    public static void defineKeys() {
        KeyGenerator generator = new KeyGenerator();

        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("rsa")
                .build();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        key1 = keys.get(1); // We need the private key

        key2 = keys.get(0); // We need the public key

        OCTGenerationParameters octGenerationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeyId("oct")
                .build();

        key3 = generator.generateKeys(octGenerationParameters).get(0);
    }

    @Test
    public void filter() {
        keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);
        keys.add(key3);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).hasSize(1);
        assertThat(data.get(0)).isEqualTo(key1);

    }

    @Test
    public void filter_symmetric() {
        keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.SYMMETRIC);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);
        keys.add(key3);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).hasSize(1);
        assertThat(data.get(0)).isEqualTo(key3);

    }

    @Test
    public void filter_NoMatch() {
        keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key3);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).isEmpty();

    }

    @Test(expected = AtbashIllegalActionException.class)
    public void filter_NullArgument() {

        keyFilter = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE);
        keyFilter.filter(null);

    }

}