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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectDecrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectEncrypter;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.text.ParseException;
import java.util.List;


/**
 * Tests JWE object methods.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWEObjectTest {

    @Test
    public void testBase64URLConstructor()
            throws Exception {

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128CBC_HS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");
        Base64URLValue fourthPart = new Base64URLValue("ghi");
        Base64URLValue fifthPart = new Base64URLValue("jkl");

        JWEObject jwe = new JWEObject(firstPart, secondPart,
                thirdPart, fourthPart,
                fifthPart);

        Assertions.assertThat(jwe.getHeader().toBase64URL()).isEqualTo(firstPart);
        Assertions.assertThat(jwe.getEncryptedKey()).isEqualTo(secondPart);
        Assertions.assertThat(jwe.getIV()).isEqualTo(thirdPart);
        Assertions.assertThat(jwe.getCipherText()).isEqualTo(fourthPart);

        Assertions.assertThat(jwe.serialize()).isEqualTo(firstPart.toString() + ".abc.def.ghi.jkl");
        Assertions.assertThat(jwe.getParsedString()).isEqualTo(firstPart + ".abc.def.ghi.jkl");

        Assertions.assertThat(jwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testHeaderLengthJustBelowLimit() throws JOSEException, ParseException {

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH - 40; i++) {
            builder.append("a");
        }

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
                .parameter("data", builder.toString())
                .build();

        Assertions.assertThat(header.toBase64URL().decodeToString()).hasSizeLessThan(Header.MAX_HEADER_STRING_LENGTH);

        JWEObject jweObject = new JWEObject(header, new Payload("example"));
        List<AtbashKey> keys = TestKeys.generateOCTKeys("kid", 128);

        jweObject.encrypt(new DirectEncrypter((SecretKey) keys.get(0).getKey()));

        String jwe = jweObject.serialize();

        jweObject = JWEObject.parse(jwe);
        jweObject.decrypt(new DirectDecrypter((SecretKey) keys.get(0).getKey()));
        Assertions.assertThat(jweObject.getPayload().toString()).isEqualTo(new Payload("example").toString());
    }

    @Test
    public void testHeaderLengthLimit() throws JOSEException {

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
            builder.append("a");
        }

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
                .parameter("data", builder.toString())
                .build();

        Assertions.assertThat(header.toBase64URL().decodeToString()).hasSizeGreaterThan(Header.MAX_HEADER_STRING_LENGTH);

        JWEObject jweObject = new JWEObject(header, new Payload("example"));

        List<AtbashKey> keys = TestKeys.generateOCTKeys("kid", 128);
        jweObject.encrypt(new DirectEncrypter((SecretKey) keys.get(0).getKey()));

        String jwe = jweObject.serialize();

        Assertions.assertThatThrownBy(
                        () -> JWEObject.parse(jwe)
                ).isInstanceOf(ParseException.class)
                .hasMessage("Invalid JWE header: The parsed string is longer than the max accepted size of " +
                        Header.MAX_HEADER_STRING_LENGTH +
                        " characters");

    }

    @Test
    public void testParseNestedJSONObjectInHeader() {

        int recursions = 8000;

        StringBuilder headerBuilder = new StringBuilder();

        for (int i = 0; i < recursions; i++) {
            headerBuilder.append("{\"\":");
        }

        String header = Base64URLValue.encode(headerBuilder.toString()).toString();
        String encryptedKey = Base64URLValue.encode("123").toString();
        String iv = Base64URLValue.encode("123").toString();
        String cipherText = Base64URLValue.encode("123").toString();
        String authTag = Base64URLValue.encode("123").toString();

        String token = header + "." + encryptedKey + "." + iv + "." + cipherText + "." + authTag;

        Assertions.assertThatThrownBy(
                        () -> JWEObject.parse(token)
                ).isInstanceOf(ParseException.class)
                .hasMessage("Invalid JWE header: The parsed string is longer than the max accepted size of " +
                        Header.MAX_HEADER_STRING_LENGTH +
                        " characters");

    }
}
