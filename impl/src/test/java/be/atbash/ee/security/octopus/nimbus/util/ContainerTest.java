/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.util;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ContainerTest {

    @Test
    public void testDefaultConstructor() {

        Container<String> container = new Container<>();
        assertThat(container.get()).isNull();
    }


    @Test
    public void testParamConstructor() {

        Container<String> container = new Container<>("abc");
        assertThat(container.get()).isEqualTo("abc");
    }


    @Test
    public void testGetAndSet() {

        Container<String> container = new Container<>();
        container.set("abc");
        assertThat(container.get()).isEqualTo("abc");
        container.set(null);
        assertThat(container.get()).isNull();
    }


    @Test
    public void testMutable() {

        Container<String> container = new Container<>("abc");
        assertThat(container.get()).isEqualTo("abc");
        container.set("def");
        assertThat(container.get()).isEqualTo("def");
    }
}
