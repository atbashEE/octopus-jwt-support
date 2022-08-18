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

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;


/**
 * Tests the key operation enumeration.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class KeyOperationTest {

    @Test
    public void testIdentifiers() {

        Assertions.assertThat(KeyOperation.SIGN.identifier()).isEqualTo("sign");
        Assertions.assertThat(KeyOperation.SIGN.toString()).isEqualTo("sign");

        Assertions.assertThat(KeyOperation.VERIFY.identifier()).isEqualTo("verify");
        Assertions.assertThat(KeyOperation.VERIFY.toString()).isEqualTo("verify");

        Assertions.assertThat(KeyOperation.ENCRYPT.identifier()).isEqualTo("encrypt");
        Assertions.assertThat(KeyOperation.ENCRYPT.toString()).isEqualTo("encrypt");

        Assertions.assertThat(KeyOperation.DECRYPT.identifier()).isEqualTo("decrypt");
        Assertions.assertThat(KeyOperation.DECRYPT.toString()).isEqualTo("decrypt");

        Assertions.assertThat(KeyOperation.WRAP_KEY.identifier()).isEqualTo("wrapKey");
        Assertions.assertThat(KeyOperation.WRAP_KEY.toString()).isEqualTo("wrapKey");

        Assertions.assertThat(KeyOperation.UNWRAP_KEY.identifier()).isEqualTo("unwrapKey");
        Assertions.assertThat(KeyOperation.UNWRAP_KEY.toString()).isEqualTo("unwrapKey");

        Assertions.assertThat(KeyOperation.DERIVE_KEY.identifier()).isEqualTo("deriveKey");
        Assertions.assertThat(KeyOperation.DERIVE_KEY.toString()).isEqualTo("deriveKey");

        Assertions.assertThat(KeyOperation.DERIVE_BITS.identifier()).isEqualTo("deriveBits");
        Assertions.assertThat(KeyOperation.DERIVE_BITS.toString()).isEqualTo("deriveBits");
    }

    @Test
    public void testParseNull()
            throws ParseException {

        Assertions.assertThat(KeyOperation.parse(null)).isNull();
    }

    @Test
    public void testParseSparseList()
            throws ParseException {

        List<String> sl = Arrays.asList("sign", null, "verify");

        Set<KeyOperation> ops = KeyOperation.parse(sl);
        Assertions.assertThat(ops.contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(ops.contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(ops.size()).isEqualTo(2);
    }

    @Test
    public void testParseList()
            throws ParseException {

        List<String> sl = Arrays.asList("sign", "verify");

        Set<KeyOperation> ops = KeyOperation.parse(sl);
        Assertions.assertThat(ops.contains(KeyOperation.SIGN)).isTrue();
        Assertions.assertThat(ops.contains(KeyOperation.VERIFY)).isTrue();
        Assertions.assertThat(ops.size()).isEqualTo(2);
    }

    @Test
    public void testParseException() {

        List<String> sl = Arrays.asList("sign", "no-such-op", "verify");

        Assertions.assertThatThrownBy(() -> KeyOperation.parse(sl))
                .isInstanceOf(ParseException.class);

    }
}
