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
package be.atbash.ee.security.octopus.keys;


import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class AtbashKeyPairTest {

    @Test
    void singlePairOfRSAKeys() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        AtbashKeyPair keyPair = new AtbashKeyPair(keys);
        Assertions.assertThat(keyPair.getKeyPair()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPublic()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPrivate()).isNotNull();
    }

    @Test
    void multiplePairOfRSAKeys() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        keys.addAll(TestKeys.generateRSAKeys("kid2"));

        Assertions.assertThatThrownBy(
                        () -> new AtbashKeyPair(keys)
                ).isInstanceOf(NotSingleKeyException.class)
                .hasMessage("Collection contained not a single type or keys with same id. ids = [kid, kid2], types = [RSA]");

    }

    @Test
    void multiplePairOfRSAKeys_filter() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        keys.addAll(TestKeys.generateRSAKeys("kid2"));

        AtbashKeyPair keyPair = new AtbashKeyPair(keys, "kid2");

        Assertions.assertThat(keyPair.getKeyPair()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPublic()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPrivate()).isNotNull();

    }

    @Test
    void multiplePairOfKeys() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        keys.addAll(TestKeys.generateECKeys("kid"));

        Assertions.assertThatThrownBy(
                        () -> new AtbashKeyPair(keys)
                ).isInstanceOf(NotSingleKeyException.class)
                .hasMessage("Collection contained not a single type or keys with same id. ids = [kid], types = [RSA, EC]");

    }

    @Test
    void onlyPrivateKey() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        List<AtbashKey> atbashKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);

        AtbashKeyPair keyPair = new AtbashKeyPair(atbashKeys);
        Assertions.assertThat(keyPair.getKeyPair()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPublic()).isNull();
        Assertions.assertThat(keyPair.getKeyPair().getPrivate()).isNotNull();
    }

    @Test
    void onlyPublicKey() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        List<AtbashKey> atbashKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);

        AtbashKeyPair keyPair = new AtbashKeyPair(atbashKeys);
        Assertions.assertThat(keyPair.getKeyPair()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPublic()).isNotNull();
        Assertions.assertThat(keyPair.getKeyPair().getPrivate()).isNull();

    }

    @Test
    void multipleKeys_private() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        keys.addAll(TestKeys.generateRSAKeys("kid"));

        Assertions.assertThatThrownBy(
                        () -> new AtbashKeyPair(keys)
                ).isInstanceOf(NotSingleKeyException.class)
                .hasMessage("Collection contained not a single key of type PRIVATE.");

    }

    @Test
    void multipleKeys_public() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        keys.addAll(TestKeys.generateRSAKeys("kid"));
        List<AtbashKey> atbashKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);

        Assertions.assertThatThrownBy(
                        () -> new AtbashKeyPair(atbashKeys)
                ).isInstanceOf(NotSingleKeyException.class)
                .hasMessage("Collection contained not a single key of type PUBLIC.");

    }
}