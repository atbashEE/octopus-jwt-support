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
package be.atbash.ee.security.octopus.nimbus.jwk;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.text.ParseException;


public class JWKMetadataTest {

    @Test
    public void testParseEmptyX509CertChain() {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add(JWKIdentifiers.X_509_CERT_CHAIN, Json.createArrayBuilder().build()); // empty

        Assertions.assertThatThrownBy(() -> JWKMetadata.parseX509CertChain(builder.build()))
                .isInstanceOf(ParseException.class)
                .hasMessage("The X.509 certificate chain \"" + JWKIdentifiers.X_509_CERT_CHAIN + "\" must not be empty");
    }

    @Test
    public void testParseNoMembers()
            throws ParseException {

        JsonObject object = Json.createObjectBuilder().build();


        Assertions.assertThat(JWKMetadata.parseKeyUse(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseKeyOperations(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseAlgorithm(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseKeyID(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertURL(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertSHA256Thumbprint(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertChain(object)).isNull();
    }


    @Test
    public void testParseNullMembers()
            throws ParseException {

        JsonObject object = Json.createObjectBuilder()
                .add(JWKIdentifiers.PUBLIC_KEY_USE, JsonValue.NULL)
                .add(JWKIdentifiers.KEY_OPS, JsonValue.NULL)
                .add(JWKIdentifiers.ALGORITHM, JsonValue.NULL)
                .add(JWKIdentifiers.KEY_ID, JsonValue.NULL)
                .add(JWKIdentifiers.X_509_URL, JsonValue.NULL)
                .add(JWKIdentifiers.X_509_CERT_SHA_1_THUMBPRINT, JsonValue.NULL)
                .add(JWKIdentifiers.X_509_CERT_SHA_256_THUMBPRINT, JsonValue.NULL)
                .add(JWKIdentifiers.X_509_CERT_CHAIN, JsonValue.NULL)
                .build();

        Assertions.assertThat(JWKMetadata.parseKeyUse(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseKeyOperations(object)).isEmpty();
        Assertions.assertThat(JWKMetadata.parseAlgorithm(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseKeyID(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertURL(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertSHA256Thumbprint(object)).isNull();
        Assertions.assertThat(JWKMetadata.parseX509CertChain(object)).isNull();

    }
}
