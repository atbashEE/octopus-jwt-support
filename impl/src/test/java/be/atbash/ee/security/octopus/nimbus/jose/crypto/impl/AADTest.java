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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.IntegerOverflowException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the Additional Authenticated Data (AAD) functions.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-06-01
 */
public class AADTest {

    @Test
    public void testComputeForJWEHeader() {

        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

        byte[] expected = jweHeader.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);

        assertThat(Arrays.equals(expected, AAD.compute(jweHeader))).isTrue();
    }

    @Test
    public void testComputeForBase64URL() {

        Base64URLValue base64URL = Base64URLValue.encode("Hello world!");

        byte[] expected = base64URL.toString().getBytes(StandardCharsets.US_ASCII);

        assertThat(Arrays.equals(expected, AAD.compute(base64URL))).isTrue();
    }

    @Test
    public void testComputeLength()
            throws IntegerOverflowException {

        byte[] aad = new byte[]{0, 1, 2, 3}; // 32 bits

        byte[] expectedBitLength = new byte[]{0, 0, 0, 0, 0, 0, 0, 32};

        assertThat(Arrays.equals(expectedBitLength, AAD.computeLength(aad))).isTrue();
    }
}
