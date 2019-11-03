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


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests plaintext JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-07-08
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
        assertThat(header.getCustomParams()).isEmpty();

        String serializedJOSEObject = plain.serialize();

        plain = PlainObject.parse(serializedJOSEObject);

        header = plain.getHeader();
        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCustomParams()).isEmpty();

        assertThat(plain.getPayload().toString()).isEqualTo("Hello world!");

        assertThat(plain.getParsedString()).isEqualTo(serializedJOSEObject);
    }
}
