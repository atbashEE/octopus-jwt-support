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
package be.atbash.ee.security.octopus.nimbus.jwk;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;


/**
 * Tests the key type class.
 */
public class KeyTypeTest {

    @Test
    public void testConstants() {

        Assertions.assertThat(KeyType.RSA.getValue()).isEqualTo("RSA");

        Assertions.assertThat(KeyType.EC.getValue()).isEqualTo("EC");

        Assertions.assertThat(KeyType.OCT.getValue()).isEqualTo("oct");

        Assertions.assertThat(KeyType.OKP.getValue()).isEqualTo("OKP");
    }

    /**
     * Test that the factory method throws an IllegalArgumentException when called with null.
     */
    @Test
    public void testIllegalArgumentException() {

        Assertions.assertThatThrownBy(
                        () -> KeyType.parse(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The key type to parse must not be null");

    }
}
