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
package be.atbash.ee.security.octopus.nimbus.util;


import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;


public class KeyUtilsTest {

    @Test
    public void testToAESSecretKey()
            throws Exception {

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey key = gen.generateKey();

        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        assertThat(key.getAlgorithm()).isEqualTo("AES");

        key = new SecretKeySpec(key.getEncoded(), "UNKNOWN");
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        assertThat(key.getAlgorithm()).isEqualTo("UNKNOWN");

        SecretKey aesKey = KeyUtils.toAESKey(key);
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        assertThat(Arrays.equals(key.getEncoded(), aesKey.getEncoded())).isTrue();
        assertThat(aesKey.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    public void testToAESSecretKey_null() {

        assertThat(KeyUtils.toAESKey(null)).isNull();
    }
}
