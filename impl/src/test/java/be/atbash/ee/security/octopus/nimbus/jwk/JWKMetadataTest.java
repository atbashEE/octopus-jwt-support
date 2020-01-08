/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jwk;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;


public class JWKMetadataTest {

    @Test
    public void testParseEmptyX509CertChain() {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("x5c", Json.createArrayBuilder().build()); // empty

        ParseException e = Assertions.assertThrows(ParseException.class,
                () -> JWKMetadata.parseX509CertChain(builder.build()));
        assertThat(e.getMessage()).isEqualTo("The X.509 certificate chain \"x5c\" must not be empty");
    }
}
