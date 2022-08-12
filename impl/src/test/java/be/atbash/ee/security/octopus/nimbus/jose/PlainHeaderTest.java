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


import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests plain header parsing and serialisation.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class PlainHeaderTest {

    @Test
    public void testMinimalConstructor()
            throws Exception {

        PlainHeader header = new PlainHeader();

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCriticalParams()).isNull();
        assertThat(header.getParsedBase64URL()).isNull();

        Base64URLValue b64url = header.toBase64URL();

        // Parse back
        header = PlainHeader.parse(b64url);

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCriticalParams()).isNull();
        assertThat(header.getParsedBase64URL()).isEqualTo(b64url);
        assertThat(header.toBase64URL()).isEqualTo(b64url);
    }

    @Test
    public void testFullAndCopyConstructors()
            throws Exception {

        Set<String> crit = new HashSet<>();
        crit.add("iat");
        crit.add("exp");
        crit.add("nbf");

        Map<String, Object> customParams = new HashMap<>();
        customParams.put("xCustom", "abc");

        PlainHeader header = new PlainHeader(
                new JOSEObjectType("JWT"),
                "application/jwt",
                crit,
                customParams,
                null);

        assertThat(header.getIncludedParameters()).containsOnly("alg", "typ", "cty", "crit", "xCustom");


        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getContentType()).isEqualTo("application/jwt");
        assertThat(header.getCriticalParams().size()).isEqualTo(3);
        assertThat(header.getCustomParameter("xCustom")).isEqualTo("abc");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);
        assertThat(header.getParsedBase64URL()).isNull();

        Base64URLValue b64url = header.toBase64URL();

        // Parse back
        header = PlainHeader.parse(b64url);

        assertThat(header.toBase64URL()).isEqualTo(b64url);

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getContentType()).isEqualTo("application/jwt");
        assertThat(header.getCriticalParams().size()).isEqualTo(3);
        assertThat(header.getCustomParameter("xCustom")).isEqualTo("abc");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);
        assertThat(header.getParsedBase64URL()).isEqualTo(b64url);

        // Copy
        header = new PlainHeader(header);

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getContentType()).isEqualTo("application/jwt");
        assertThat(header.getCriticalParams().size()).isEqualTo(3);
        assertThat(header.getCustomParameter("xCustom")).isEqualTo("abc");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);
        assertThat(header.getParsedBase64URL()).isEqualTo(b64url);
    }

    @Test
    public void testBuilder()
            throws Exception {

        Set<String> crit = new HashSet<>();
        crit.add("iat");
        crit.add("exp");
        crit.add("nbf");

        PlainHeader header = new PlainHeader.Builder().
                type(new JOSEObjectType("JWT")).
                contentType("application/jwt").
                criticalParams(crit).
                parameter("xCustom", "abc").
                build();

        assertThat(header.getIncludedParameters()).containsOnly("alg", "typ", "cty", "crit", "xCustom");

        Base64URLValue b64url = header.toBase64URL();

        // Parse back
        header = PlainHeader.parse(b64url);

        assertThat(header.toBase64URL()).isEqualTo(b64url);

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getContentType()).isEqualTo("application/jwt");
        assertThat(header.getCriticalParams().size()).isEqualTo(3);
        assertThat(header.getCustomParameter("xCustom")).isEqualTo("abc");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);
    }

    @Test
    public void testParseExample()
            throws Exception {

        // Example BASE64URL from JWT spec
        Base64URLValue in = new Base64URLValue("eyJhbGciOiJub25lIn0");

        PlainHeader header = PlainHeader.parse(in);

        assertThat(header.toBase64URL()).isEqualTo(in);

        assertThat(header.getAlgorithm()).isEqualTo(Algorithm.NONE);
    }

    @Test
    public void testBuilderWithCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put(JWKIdentifiers.X_COORD, "1");
        customParams.put(JWKIdentifiers.Y_COORD, "2");

        PlainHeader header = new PlainHeader.Builder().
                parameters(customParams).
                build();

        assertThat(header.getCustomParameter("x")).isEqualTo("1");
        assertThat(header.getCustomParameter("y")).isEqualTo("2");
        assertThat(header.getCustomParameters().size()).isEqualTo(2);
    }

    @Test
    // iss #333
    public void testParseHeaderWithNullTyp()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add(HeaderParameterNames.ALGORITHM, Algorithm.NONE.getName());
        builder.addNull(HeaderParameterNames.TYPE);
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(2);

        Header header = PlainHeader.parse(jsonObject);
        assertThat(header.getType()).isNull();
    }

    @Test
    // iss #334
    public void testParseHeaderWithNullCrit()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add(HeaderParameterNames.ALGORITHM, Algorithm.NONE.getName());
        builder.addNull(HeaderParameterNames.TYPE);
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(2);

        Header header = PlainHeader.parse(jsonObject);
        assertThat(header.getCriticalParams()).isNull();
    }
}

