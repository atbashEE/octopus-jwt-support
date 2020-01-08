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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the key length exception.
 */
public class KeyLengthExceptionTest {


    @Test
    public void testMessageConstructor() {

        KeyLengthException e = new KeyLengthException("abc");

        assertThat(e.getMessage()).isEqualTo("abc");
        assertThat(e.getExpectedKeyLength()).isEqualTo(0);
        assertThat(e.getAlgorithm()).isNull();
    }


    @Test
    public void testDetailConstructor() {

        KeyLengthException e = new KeyLengthException(128, EncryptionMethod.A128GCM);

        assertThat(e.getMessage()).isEqualTo("The expected key length is 128 bits (for A128GCM algorithm)");
        assertThat(e.getExpectedKeyLength()).isEqualTo(128);
        assertThat(e.getAlgorithm()).isEqualTo(EncryptionMethod.A128GCM);
    }
}
