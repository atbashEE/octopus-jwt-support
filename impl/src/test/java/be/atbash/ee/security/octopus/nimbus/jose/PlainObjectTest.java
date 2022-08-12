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


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests plaintext JOSE object parsing and serialisation.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class PlainObjectTest {

    @Test
    public void testSerializeAndParse()
            throws Exception {

        Payload payload = new Payload("Hello world!");

        PlainObject plain = new PlainObject(payload);

        assertThat(plain.getHeader()).isNotNull();
        assertThat(plain.getPayload().toString()).isEqualTo("Hello world!");

        PlainHeader header = plain.getHeader();
        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCustomParameters()).isEmpty();

        String serializedJOSEObject = plain.serialize();

        plain = PlainObject.parse(serializedJOSEObject);

        header = plain.getHeader();
        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCustomParameters()).isEmpty();

        assertThat(plain.getPayload().toString()).isEqualTo("Hello world!");

        assertThat(plain.getParsedString()).isEqualTo(serializedJOSEObject);
    }

    @Test
    public void testHeaderLengthJustBelowLimit() throws ParseException {

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH - 30; i++) {
            builder.append("a");
        }

        PlainHeader header = new PlainHeader.Builder()
                .parameter("data", builder.toString())
                .build();

        Assertions.assertThat(header.toBase64URL().decodeToString()).hasSizeLessThan(Header.MAX_HEADER_STRING_LENGTH);

        PlainObject plainObject = new PlainObject(header, new Payload("example"));

        String plainJOSE = plainObject.serialize();

        plainObject = PlainObject.parse(plainJOSE);
        Assertions.assertThat(plainObject.getHeader().toString()).isEqualTo(header.toString());
    }

    @Test
    public void testHeaderLengthLimitExceeded() {

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
            builder.append("a");
        }

        PlainHeader header = new PlainHeader.Builder()
                .parameter("data", builder.toString())
                .build();

        Assertions.assertThat(header.toBase64URL().decodeToString()).hasSizeGreaterThan(Header.MAX_HEADER_STRING_LENGTH);

        PlainObject plainObject = new PlainObject(header, new Payload("example"));

        String plainJOSE = plainObject.serialize();

        Assertions.assertThatThrownBy(
                        () -> PlainObject.parse(plainJOSE)
                ).isInstanceOf(ParseException.class)
                .hasMessage(
                        "Invalid unsecured header: The parsed string is longer than the max accepted size of " +
                                Header.MAX_HEADER_STRING_LENGTH +
                                " characters"
                );

    }
}
