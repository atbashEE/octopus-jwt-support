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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.utils;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests the array utilities.
 */
public class ConstantTimeUtilsTest {

    @Test
    public void testEquality() {

        byte[] a = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] b = {1, 2, 3, 4, 5, 6, 7, 8};

        Assertions.assertThat(ConstantTimeUtils.areEqual(a, b)).isTrue();
    }

    @Test
    public void testInequality() {

        byte[] a = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] b = {1, 2, 3, 4, 5, 6, 7, 7};

        Assertions.assertThat(ConstantTimeUtils.areEqual(a, b)).isFalse();
    }

    @Test
    public void testLengthMismatch() {

        byte[] a = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] b = {1, 2, 3, 4, 5, 6, 7};

        Assertions.assertThat(ConstantTimeUtils.areEqual(a, b)).isFalse();
    }
}
