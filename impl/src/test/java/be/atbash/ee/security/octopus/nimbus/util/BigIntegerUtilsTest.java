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

import java.math.BigInteger;



/**
 * Tests the big integer utility.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest {

    @Test
    public void testNoLeadingZero() {

        byte[] a1 = BigIntegerUtils.toBytesUnsigned(new BigInteger("123456789A", 16));
        byte[] a2 = BigIntegerUtils.toBytesUnsigned(new BigInteger("F23456789A", 16));

        Assertions.assertThat(a2.length).isEqualTo(a1.length);
    }

    @Test
    public void testBigIntegerConstructor_byteArray() {

        BigInteger bigInteger = new BigInteger("123456789");

        byte[] bytes = bigInteger.toByteArray();
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytes));

        bytes = BigIntegerUtils.toBytesUnsigned(bigInteger);
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytes));

    }

    @Test
    public void testBigIntegerConstructor_byteArray_leadingZeroPadded() {

        BigInteger bigInteger = new BigInteger("123456789");

        byte[] bytes = bigInteger.toByteArray();
        byte[] bytesZeroPadded = ByteUtils.concat(new byte[1], bytes);
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytesZeroPadded));

        bytes = BigIntegerUtils.toBytesUnsigned(bigInteger);
        bytesZeroPadded = ByteUtils.concat(new byte[1], bytes);
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytesZeroPadded));
    }

    @Test
    public void testBigIntegerConstructor_byteArray_leadingZeroPaddedMultiple() {

        BigInteger bigInteger = new BigInteger("123456789");

        int numZeroBytes = 10;

        byte[] bytes = bigInteger.toByteArray();
        byte[] bytesZeroPadded = ByteUtils.concat(new byte[numZeroBytes], bytes);
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytesZeroPadded));

        bytes = BigIntegerUtils.toBytesUnsigned(bigInteger);
        bytesZeroPadded = ByteUtils.concat(new byte[numZeroBytes], bytes);
        Assertions.assertThat(bigInteger).isEqualTo(new BigInteger(1, bytesZeroPadded));
    }
}
