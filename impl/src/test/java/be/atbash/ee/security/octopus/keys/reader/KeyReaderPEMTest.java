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

import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class KeyReaderPEMTest {

    private final KeyReaderPEM reader = new KeyReaderPEM();

    @Test
    public void readResource() {
        Assertions.assertThatThrownBy(() -> reader.readResource("./not-existent", new TestPasswordLookup()))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    public void readResourceString() {
        String content = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyJz0jSniDu+6tzToc3ci\n" +
                "7Nr2+UKZWYIaFIUwiELy0jvYefqJtKP0bqgC5mrN1GBfV1f4Q5qWWD34Ngahk05O\n" +
                "Mc8iyfmd1a1VDXBnc5d8gZuqRZGXctJQ5Ez/1nhLxeW3aPdEm6ZiC9J1dZRjVgkQ\n" +
                "YCTzaF8LW7V33EUuz1fXME46su239E0lQzLhVs2WJ61tKu50JFgEz7m4z9Qd60fj\n" +
                "zxzCnhT7Aug5qltEqWwLvgZspzGAU96IntI0wmGCw/1r8qcw+ZK4/qN1r/ABWad2\n" +
                "Br3wLdaIc54gP9FrSwuY2omlEtAcZkDIuCbMBIG4D5DaMuvkCJ9VQGx7ZTQtuqen\n" +
                "kQIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";
        List<AtbashKey> atbashKeys = reader.parseContent(content, null);
        Assertions.assertThat(atbashKeys).hasSize(1);
        Assertions.assertThat(atbashKeys.get(0).getSecretKeyType()).isEqualTo(new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC));
    }

}