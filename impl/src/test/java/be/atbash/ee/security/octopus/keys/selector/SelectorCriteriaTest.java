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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.fake.FakeRSAPublic;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

public class SelectorCriteriaTest {


    @Test
    public void testBuilder() throws URISyntaxException {
        SelectorCriteria.Builder builder = SelectorCriteria.newBuilder();

        builder.withId("kid");
        builder.withKeyType(KeyType.RSA);

        SecretKeyType secretKeyType = SecretKeyType.fromKey(new FakeRSAPublic());
        builder.withSecretKeyType(secretKeyType);

        builder.withAsymmetricPart(AsymmetricPart.PUBLIC);
        builder.withJKU(new URI("http://jkuURL"));

        Long discriminator = 123L;
        builder.withDiscriminator(discriminator);

        SelectorCriteria criteria = builder.build();

        Assertions.assertThat(criteria.getId()).isEqualTo("kid");
        Assertions.assertThat(criteria.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(criteria.getSecretKeyType()).isEqualTo(secretKeyType);
        Assertions.assertThat(criteria.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
        Assertions.assertThat(criteria.getJku().toString()).isEqualTo("http://jkuURL");

        Object d = criteria.getDiscriminator();
        Assertions.assertThat(d).isInstanceOf(Long.class);
        Assertions.assertThat(d).isEqualTo(123L);
    }

    @Test
    public void testBuilder_withExistingCriteria() throws URISyntaxException {
        SelectorCriteria.Builder builder = SelectorCriteria.newBuilder();

        builder.withId("kid");
        builder.withKeyType(KeyType.RSA);

        SecretKeyType secretKeyType = SecretKeyType.fromKey(new FakeRSAPublic());
        builder.withSecretKeyType(secretKeyType);

        builder.withAsymmetricPart(AsymmetricPart.PUBLIC);
        builder.withJKU(new URI("http://jkuURL"));

        Long discriminator = 123L;
        builder.withDiscriminator(discriminator);

        SelectorCriteria criteriaTemp = builder.build();

        builder = SelectorCriteria.newBuilder(criteriaTemp);
        builder.withId("new-kid");
        builder.withAsymmetricPart(null);

        SelectorCriteria criteria = builder.build();

        Assertions.assertThat(criteria.getId()).isEqualTo("new-kid");
        Assertions.assertThat(criteria.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(criteria.getSecretKeyType()).isEqualTo(secretKeyType);
        Assertions.assertThat(criteria.getAsymmetricPart()).isNull();
        Assertions.assertThat(criteria.getJku().toString()).isEqualTo("http://jkuURL");

        Object d = criteria.getDiscriminator();
        Assertions.assertThat(d).isInstanceOf(Long.class);
        Assertions.assertThat(d).isEqualTo(123L);
    }
}