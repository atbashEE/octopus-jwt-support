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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
 */
public class Base64URLValueTest {


    // Test byte array
    private static final byte[] BYTES = {0x3, (byte) 236, (byte) 255, (byte) 224, (byte) 193};


    // Test JSON string
    private static final String JSON_STRING = "{\"iss\":\"joe\",\r\n" +
            " \"exp\":1300819380,\r\n" +
            " \"http://example.com/is_root\":true}";


    // Test big integer
    private static final BigInteger BIGINT = new BigInteger("9999999999999999999999999999999999");


    @Test
    public void testByteArrayEncodeAndDecode() {

        assertThat(Base64URLValue.encode(BYTES).toString()).isEqualTo("A-z_4ME");

        byte[] decoded = new Base64URLValue("A-z_4ME").decode();

        assertThat(decoded.length).isEqualTo(BYTES.length);
        assertThat(decoded[0]).isEqualTo(BYTES[0]);
        assertThat(decoded[1]).isEqualTo(BYTES[1]);
        assertThat(decoded[2]).isEqualTo(BYTES[2]);
        assertThat(decoded[3]).isEqualTo(BYTES[3]);
    }

    @Test
    public void testEncodeAndDecode() {

        byte[] bytes = JSON_STRING.getBytes(StandardCharsets.UTF_8);

        Base64URLValue b64url = Base64URLValue.encode(bytes);

        String expected = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        assertThat(b64url.toString()).isEqualTo(expected);
    }

    @Test
    public void testBigIntegerEncodeAndDecode() {

        Base64URLValue b64url = Base64URLValue.encode(BIGINT);

        assertThat(b64url.decodeToBigInteger()).isEqualTo(BIGINT);
    }

    @Test
    public void testFrom() {

        Base64URLValue base64URL = Base64URLValue.encode("foobar");

        Base64URLValue base64From = Base64URLValue.from(base64URL.toString());
        assertThat(base64From).isEqualTo(base64URL);
    }

    @Test
    public void testFromNull() {

        assertThat(Base64URLValue.from(null)).isNull();
    }
}

