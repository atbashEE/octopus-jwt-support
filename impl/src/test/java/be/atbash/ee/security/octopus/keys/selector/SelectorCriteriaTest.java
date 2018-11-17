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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.fake.FakeRSAPublic;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;

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

        assertThat(criteria.getId()).isEqualTo("kid");
        assertThat(criteria.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(criteria.getSecretKeyType()).isEqualTo(secretKeyType);
        assertThat(criteria.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
        assertThat(criteria.getJku().toString()).isEqualTo("http://jkuURL");

        Object d = criteria.getDiscriminator();
        assertThat(d).isInstanceOf(Long.class);
        assertThat(d).isEqualTo(123L);
    }
}