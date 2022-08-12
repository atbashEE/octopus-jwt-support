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
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the base JOSE header class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class HeaderTest {

    @Test
    public void testParsePlainHeaderFromBase64URL()
            throws Exception {

        // Example BASE64URL from JWT spec
        Base64URLValue in = new Base64URLValue("eyJhbGciOiJub25lIn0");

        Header header = Header.parse(in);

        assertThat(header).isInstanceOf(PlainHeader.class);
        assertThat(header.toBase64URL()).isEqualTo(in);
        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
    }


    @Test
    public void testParseJWSHeaderFromBase64URL()
            throws Exception {

        // Example BASE64URL from JWS spec
        Base64URLValue in = new Base64URLValue("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        Header header = Header.parse(in);

        assertThat(header).isInstanceOf(JWSHeader.class);
        assertThat(header.toBase64URL()).isEqualTo(in);
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void testParseJWEHeaderFromBase64URL()
            throws Exception {

        // Example BASE64URL from JWE spec
        Base64URLValue in = new Base64URLValue("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

        Header header = Header.parse(in);

        assertThat(header).isInstanceOf(JWEHeader.class);
        assertThat(header.toBase64URL()).isEqualTo(in);
        assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);

        JWEHeader jweHeader = (JWEHeader) header;
        assertThat(jweHeader.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128CBC_HS256);
    }

    @Test
    public void testParseAlgorithm_nullAlg() {

        Assertions.assertThatThrownBy(() -> Header.parse("{}"))
                .isInstanceOf(ParseException.class)
                .hasMessage("Missing 'alg' in JSON object");
    }

}
