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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the byte utilities.
 */
public class ByteUtilsTest {


    @Test
    public void testConcat() {

        byte[] a1 = {(byte) 1, (byte) 2};
        byte[] a2 = {(byte) 3, (byte) 4};

        byte[] out = ByteUtils.concat(a1, a2);

        assertThat(out).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
    }

    @Test
    public void testConcatWithNullValue() {

        byte[] a1 = {(byte) 1, (byte) 2};
        byte[] a2 = null;
        byte[] a3 = {(byte) 3, (byte) 4};

        byte[] out = ByteUtils.concat(a1, a2, a3);

        assertThat(out).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
    }

    @Test
    public void testHashTruncation()
            throws Exception {

        byte[] hash = MessageDigest.getInstance("SHA-256").digest("Hello, world!".getBytes(StandardCharsets.UTF_8));

        byte[] firstHalf = ByteUtils.subArray(hash, ByteUtils.byteLength(0), ByteUtils.byteLength(128));
        byte[] secondHalf = ByteUtils.subArray(hash, ByteUtils.byteLength(128), ByteUtils.byteLength(128));

        byte[] concat = ByteUtils.concat(firstHalf, secondHalf);

        assertThat(Base64URLValue.encode(hash)).isEqualTo(Base64URLValue.encode(concat));
    }

    @Test
    public void testSafeBitLength_OK() {

        assertThat(ByteUtils.bitLength(1)).isEqualTo(8);
        assertThat(ByteUtils.bitLength(2)).isEqualTo(16);
        assertThat(ByteUtils.bitLength(4)).isEqualTo(32);
        assertThat(ByteUtils.bitLength(8)).isEqualTo(64);
    }

    @Test
    public void testSafeBitLength_IntegerOverflow() {

        try {
            ByteUtils.safeBitLength(Integer.MAX_VALUE);
            fail();
        } catch (IntegerOverflowException e) {
            assertThat(e.getMessage()).isEqualTo("Integer overflow");
        }
    }

    @Test
    public void testArraySafeBitLength_OK() {

        assertThat(ByteUtils.bitLength(new byte[1])).isEqualTo(8);
        assertThat(ByteUtils.bitLength(new byte[2])).isEqualTo(16);
        assertThat(ByteUtils.bitLength(new byte[4])).isEqualTo(32);
        assertThat(ByteUtils.bitLength(new byte[8])).isEqualTo(64);
    }

    @Test
    public void testArraySafeBitLength_IntegerOverflow() {

        try {
            ByteUtils.safeBitLength(new byte[Integer.MAX_VALUE]);
            fail();
        } catch (OutOfMemoryError e) {
            System.out.println("Test not run due to " + e);
        } catch (IntegerOverflowException e) {
            assertThat(e.getMessage()).isEqualTo("Integer overflow");
        }
    }
}
