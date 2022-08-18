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
package be.atbash.ee.security.octopus.config;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

public class PemKeyEncryptionTest {

    @Test
    public void parse() {
        PemKeyEncryption value = PemKeyEncryption.parse("PKCS8");
        Assertions.assertThat(value).isEqualTo(PemKeyEncryption.PKCS8);
    }

    @Test
    public void parse_modified() {
        PemKeyEncryption value = PemKeyEncryption.parse(" pkcs#1  ");
        Assertions.assertThat(value).isEqualTo(PemKeyEncryption.PKCS1);
    }

    @Test
    public void parse_empty() {
        PemKeyEncryption value = PemKeyEncryption.parse("  ");
        Assertions.assertThat(value).isNull();
    }

    @Test
    public void parse_null() {
        PemKeyEncryption value = PemKeyEncryption.parse(null);
        Assertions.assertThat(value).isNull();
    }
}