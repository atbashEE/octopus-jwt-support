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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;


/**
 * Tests the byte utilities.
 */
public class ByteUtilsTest {


    @Test
    public void testConcat() {

        byte[] a1 = {(byte) 1, (byte) 2};
        byte[] a2 = {(byte) 3, (byte) 4};

        byte[] out = ByteUtils.concat(a1, a2);

        Assertions.assertThat(out).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
    }

    @Test
    public void testConcatWithNullValue() {

        byte[] a1 = {(byte) 1, (byte) 2};
        byte[] a2 = null;
        byte[] a3 = {(byte) 3, (byte) 4};

        byte[] out = ByteUtils.concat(a1, a2, a3);

        Assertions.assertThat(out).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
    }

    @Test
    public void testHashTruncation()
            throws Exception {

        byte[] hash = MessageDigest.getInstance("SHA-256").digest("Hello, world!".getBytes(StandardCharsets.UTF_8));

        byte[] firstHalf = ByteUtils.subArray(hash, ByteUtils.byteLength(0), ByteUtils.byteLength(128));
        byte[] secondHalf = ByteUtils.subArray(hash, ByteUtils.byteLength(128), ByteUtils.byteLength(128));

        byte[] concat = ByteUtils.concat(firstHalf, secondHalf);

        Assertions.assertThat(Base64URLValue.encode(hash)).isEqualTo(Base64URLValue.encode(concat));
    }

    @Test
    public void testSafeBitLength_OK() {

        Assertions.assertThat(ByteUtils.bitLength(1)).isEqualTo(8);
        Assertions.assertThat(ByteUtils.bitLength(2)).isEqualTo(16);
        Assertions.assertThat(ByteUtils.bitLength(4)).isEqualTo(32);
        Assertions.assertThat(ByteUtils.bitLength(8)).isEqualTo(64);
    }

    @Test
    public void testSafeBitLength_IntegerOverflow() {

        Assertions.assertThatThrownBy(
                        () -> ByteUtils.safeBitLength(Integer.MAX_VALUE))
                .isInstanceOf(IntegerOverflowException.class)
                .hasMessage("Integer overflow");

    }

    @Test
    public void testArraySafeBitLength_OK() {

        Assertions.assertThat(ByteUtils.bitLength(new byte[1])).isEqualTo(8);
        Assertions.assertThat(ByteUtils.bitLength(new byte[2])).isEqualTo(16);
        Assertions.assertThat(ByteUtils.bitLength(new byte[4])).isEqualTo(32);
        Assertions.assertThat(ByteUtils.bitLength(new byte[8])).isEqualTo(64);
    }

    @Test
    public void testArraySafeBitLength_IntegerOverflow() {

        Assertions.assertThatThrownBy(
                        () -> ByteUtils.safeBitLength(new byte[Integer.MAX_VALUE / 8 + 1]))
                .isInstanceOf(IntegerOverflowException.class)
                .hasMessage("Integer overflow");

    }

    @Test
    public void testConcatSignatureAllZeroes() {

        Assertions.assertThat(ByteUtils.isZeroFilled(new byte[64])).isTrue();

        byte[] array = new byte[64];
        Arrays.fill(array, Byte.MAX_VALUE);
        Assertions.assertThat(ByteUtils.isZeroFilled(array)).isFalse();

        array = new byte[64];
        array[63] = 1;
        Assertions.assertThat(ByteUtils.isZeroFilled(array)).isFalse();

        Assertions.assertThatThrownBy(() -> ByteUtils.isZeroFilled(null))
                .isInstanceOf(NullPointerException.class);
    }
}
