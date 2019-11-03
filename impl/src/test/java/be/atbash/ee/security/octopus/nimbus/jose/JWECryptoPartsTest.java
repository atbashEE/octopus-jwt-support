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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWE crypto parts class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-11
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


        assertThat(parts.getHeader()).isNull();
        assertThat(parts.getEncryptedKey().toString()).isEqualTo("abc");
        assertThat(parts.getInitializationVector().toString()).isEqualTo("def");
        assertThat(parts.getCipherText().toString()).isEqualTo("ghi");
        assertThat(parts.getAuthenticationTag().toString()).isEqualTo("jkl");
    }

    @Test
    public void testConstructorWithoutHeader2() {

        JWECryptoParts parts = new JWECryptoParts(null, null, new Base64URLValue("abc"), null);

        assertThat(parts.getHeader()).isNull();
        assertThat(parts.getEncryptedKey()).isNull();
        assertThat(parts.getInitializationVector()).isNull();
        assertThat(parts.getCipherText().toString()).isEqualTo("abc");
        assertThat(parts.getAuthenticationTag()).isNull();
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

        assertThat(parts.getHeader()).isEqualTo(header);
        assertThat(parts.getEncryptedKey().toString()).isEqualTo("abc");
        assertThat(parts.getInitializationVector().toString()).isEqualTo("def");
        assertThat(parts.getCipherText().toString()).isEqualTo("ghi");
        assertThat(parts.getAuthenticationTag().toString()).isEqualTo("jkl");
    }


}
