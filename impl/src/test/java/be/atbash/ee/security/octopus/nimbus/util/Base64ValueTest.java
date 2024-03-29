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
package be.atbash.ee.security.octopus.nimbus.util;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;


/**
 * Tests the Base64URL class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class Base64ValueTest {


    @Test
    public void testEncode() {

        // Test vector from rfc4648#section-10
        Base64Value b64 = Base64Value.encode("foobar");
        Assertions.assertThat(b64.toString()).isEqualTo("Zm9vYmFy");
    }

    @Test
    public void testDecode() {

        // Test vector from rfc4648#section-10
        Base64Value b64 = new Base64Value("Zm9vYmFy");
        Assertions.assertThat(b64.decodeToString()).isEqualTo("foobar");
    }

    @Test
    public void testFrom() {

        Base64Value b64 = Base64Value.encode("foobar");
        Assertions.assertThat(b64.toString()).isEqualTo("Zm9vYmFy");

        Base64Value base64From = Base64Value.from(b64.toString());
        Assertions.assertThat(base64From).isEqualTo(b64);
    }

    @Test
    public void testFromNull() {

        Assertions.assertThat(Base64Value.from(null)).isNull();
    }
}

