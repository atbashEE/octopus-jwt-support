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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;


public class KeyUtilsTest {

    @Test
    public void testToAESSecretKey()
            throws Exception {

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey key = gen.generateKey();

        Assertions.assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo("AES");

        key = new SecretKeySpec(key.getEncoded(), "UNKNOWN");
        Assertions.assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        Assertions.assertThat(key.getAlgorithm()).isEqualTo("UNKNOWN");

        SecretKey aesKey = KeyUtils.toAESKey(key);
        Assertions.assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);
        Assertions.assertThat(Arrays.equals(key.getEncoded(), aesKey.getEncoded())).isTrue();
        Assertions.assertThat(aesKey.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    public void testToAESSecretKey_null() {

        Assertions.assertThat(KeyUtils.toAESKey(null)).isNull();
    }
}
