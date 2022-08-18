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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Test;

import org.assertj.core.api.Assertions;


/**
 * Tests the JWE crypto parts class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWECryptoPartsTest {


    @Test
    public void testConstructorWithoutHeader() {

        JWECryptoParts parts = new JWECryptoParts(
                new Base64URLValue("abc"),
                new Base64URLValue("def"),
                new Base64URLValue("ghi"),
                new Base64URLValue("jkl")
        );


        Assertions.assertThat(parts.getHeader()).isNull();
        Assertions.assertThat(parts.getEncryptedKey().toString()).isEqualTo("abc");
        Assertions.assertThat(parts.getInitializationVector().toString()).isEqualTo("def");
        Assertions.assertThat(parts.getCipherText().toString()).isEqualTo("ghi");
        Assertions.assertThat(parts.getAuthenticationTag().toString()).isEqualTo("jkl");
    }

    @Test
    public void testConstructorWithoutHeader2() {

        JWECryptoParts parts = new JWECryptoParts(null, null, new Base64URLValue("abc"), null);

        Assertions.assertThat(parts.getHeader()).isNull();
        Assertions.assertThat(parts.getEncryptedKey()).isNull();
        Assertions.assertThat(parts.getInitializationVector()).isNull();
        Assertions.assertThat(parts.getCipherText().toString()).isEqualTo("abc");
        Assertions.assertThat(parts.getAuthenticationTag()).isNull();
    }


    @Test
    public void testConstructorWithHeader() {

        JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

        JWECryptoParts parts = new JWECryptoParts(
                header,
                new Base64URLValue("abc"),
                new Base64URLValue("def"),
                new Base64URLValue("ghi"),
                new Base64URLValue("jkl")
        );

        Assertions.assertThat(parts.getHeader()).isEqualTo(header);
        Assertions.assertThat(parts.getEncryptedKey().toString()).isEqualTo("abc");
        Assertions.assertThat(parts.getInitializationVector().toString()).isEqualTo("def");
        Assertions.assertThat(parts.getCipherText().toString()).isEqualTo("ghi");
        Assertions.assertThat(parts.getAuthenticationTag().toString()).isEqualTo("jkl");
    }


}
