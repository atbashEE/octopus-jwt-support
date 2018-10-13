/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTEncoderTest {

    @Test
    public void encodeObject_json() {

        Payload payload = new Payload();
        payload.setValue("Spock");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

        JWTParameters parameters = new JWTParametersNone();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(payload, parameters);

        // Can't use equals checks as order of elements in JSON aren't defined.
        assertThat(json).contains("\"number\":42");
        assertThat(json).isEqualTo("\"myList\":[\"permission1\",\"permission2\"]");
        assertThat(json).isEqualTo("\"value\":\"Spock\"");
    }

}