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
package be.atbash.ee.security.octopus.keys.reader;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 */

public class DefaultKeyResourceTypeProviderTest {

    private final KeyResourceTypeProvider provider = new DefaultKeyResourceTypeProvider();

    @Test
    public void determineKeyResourceType() {
        Assertions.assertThat(provider.determineKeyResourceType("test.pem")).isEqualTo(KeyResourceType.PEM);
    }

    @Test
    public void determineKeyResourceType_2() {
        Assertions.assertThat(provider.determineKeyResourceType("test.jwks")).isEqualTo(KeyResourceType.JWKSET);
    }

    @Test
    public void determineKeyResourceType_unknown() {
        Assertions.assertThat(provider.determineKeyResourceType("test.unkown")).isNull();
    }

    @Test
    public void determineKeyResourceType_unknown2() {
        Assertions.assertThat(provider.determineKeyResourceType("test")).isNull();
    }
}