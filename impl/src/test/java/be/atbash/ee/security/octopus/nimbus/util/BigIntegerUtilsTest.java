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

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the big integer utility.
 *
 * @author Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest {

    @Test
    public void testNoLeadingZero() {

        byte[] a1 = BigIntegerUtils.toBytesUnsigned(new BigInteger("123456789A", 16));
        byte[] a2 = BigIntegerUtils.toBytesUnsigned(new BigInteger("F23456789A", 16));

        assertThat(a2.length).isEqualTo(a1.length);
    }
}
