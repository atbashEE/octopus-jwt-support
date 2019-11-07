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
package be.atbash.ee.security.octopus.nimbus.jwk;


import junit.framework.TestCase;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the key operation enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-04-03
 */
public class KeyOperationTest extends TestCase {


    public void testIdentifiers() {

        assertThat(KeyOperation.SIGN.identifier()).isEqualTo("sign");
        assertThat(KeyOperation.SIGN.toString()).isEqualTo("sign");

        assertThat(KeyOperation.VERIFY.identifier()).isEqualTo("verify");
        assertThat(KeyOperation.VERIFY.toString()).isEqualTo("verify");

        assertThat(KeyOperation.ENCRYPT.identifier()).isEqualTo("encrypt");
        assertThat(KeyOperation.ENCRYPT.toString()).isEqualTo("encrypt");

        assertThat(KeyOperation.DECRYPT.identifier()).isEqualTo("decrypt");
        assertThat(KeyOperation.DECRYPT.toString()).isEqualTo("decrypt");

        assertThat(KeyOperation.WRAP_KEY.identifier()).isEqualTo("wrapKey");
        assertThat(KeyOperation.WRAP_KEY.toString()).isEqualTo("wrapKey");

        assertThat(KeyOperation.UNWRAP_KEY.identifier()).isEqualTo("unwrapKey");
        assertThat(KeyOperation.UNWRAP_KEY.toString()).isEqualTo("unwrapKey");

        assertThat(KeyOperation.DERIVE_KEY.identifier()).isEqualTo("deriveKey");
        assertThat(KeyOperation.DERIVE_KEY.toString()).isEqualTo("deriveKey");

        assertThat(KeyOperation.DERIVE_BITS.identifier()).isEqualTo("deriveBits");
        assertThat(KeyOperation.DERIVE_BITS.toString()).isEqualTo("deriveBits");
    }


    public void testParseNull()
            throws ParseException {

        assertThat(KeyOperation.parse(null)).isNull();
    }


    public void testParseSparseList()
            throws ParseException {

        List<String> sl = Arrays.asList("sign", null, "verify");

        Set<KeyOperation> ops = KeyOperation.parse(sl);
        assertThat(ops.contains(KeyOperation.SIGN)).isTrue();
        assertThat(ops.contains(KeyOperation.VERIFY)).isTrue();
        assertThat(ops.size()).isEqualTo(2);
    }


    public void testParseList()
            throws ParseException {

        List<String> sl = Arrays.asList("sign", "verify");

        Set<KeyOperation> ops = KeyOperation.parse(sl);
        assertThat(ops.contains(KeyOperation.SIGN)).isTrue();
        assertThat(ops.contains(KeyOperation.VERIFY)).isTrue();
        assertThat(ops.size()).isEqualTo(2);
    }


    public void testParseException() {

        List<String> sl = Arrays.asList("sign", "no-such-op", "verify");

        try {
            KeyOperation.parse(sl);
            fail();
        } catch (ParseException e) {
            // ok
        }
    }
}
