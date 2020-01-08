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
package be.atbash.ee.security.octopus.keys.selector.filter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class IdKeyFilterTest {

    private static AtbashKey key1;
    private static AtbashKey key2;

    private KeyFilter keyFilter;

    @BeforeAll
    public static void defineKeys() {
        KeyGenerator generator = new KeyGenerator();

        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        key1 = keys.get(0); // It doesn't really matter, but we just need a value

        generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("test")
                .build();
        keys = generator.generateKeys(generationParameters);

        key2 = keys.get(0);
    }

    @Test
    public void filter() {
        keyFilter = new IdKeyFilter("kid");

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key1);
        keys.add(key2);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).hasSize(1);
        assertThat(data.get(0)).isEqualTo(key1);
    }

    @Test
    public void filter_NoMatch() {
        keyFilter = new IdKeyFilter("kid");

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key2);

        List<AtbashKey> data = keyFilter.filter(keys);

        assertThat(data).isEmpty();

    }

    @Test
    public void filter_NullArgument() {
        keyFilter = new IdKeyFilter("kid");

        Assertions.assertThrows(AtbashIllegalActionException.class, () -> keyFilter.filter(null));

    }

    @Test
    public void filter_NullKeyId() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> keyFilter = new IdKeyFilter(null));

    }

    @Test
    public void filter_NullKeyId2() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> keyFilter = new IdKeyFilter(""));

    }
}