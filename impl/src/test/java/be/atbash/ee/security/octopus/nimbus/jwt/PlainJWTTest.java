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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.PlainHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;

public class PlainJWTTest {

    @Test
    public void testClaimsSetConstructor()
            throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("http://c2id.com")
                .audience("http://app.example.com")
                .build();

        PlainJWT jwt = new PlainJWT(claimsSet);

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        Assertions.assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://c2id.com");
        Assertions.assertThat(jwt.getJWTClaimsSet().getAudience().get(0)).isEqualTo("http://app.example.com");
    }

    @Test
    public void testHeaderAndClaimsSetConstructor()
            throws Exception {

        PlainHeader header = new PlainHeader.Builder().parameter(JWTClaimNames.EXPIRATION_TIME, 1000L).build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("http://c2id.com")
                .audience("http://app.example.com")
                .build();

        PlainJWT jwt = new PlainJWT(header, claimsSet);

        Assertions.assertThat(jwt.getHeader()).isEqualTo(header);

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        Assertions.assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://c2id.com");
        Assertions.assertThat(jwt.getJWTClaimsSet().getAudience().get(0)).isEqualTo("http://app.example.com");
    }

    @Test
    public void testBase64URLConstructor()
            throws Exception {

        // {"alg":"none"}
        Base64URLValue part1 = new Base64URLValue("eyJhbGciOiJub25lIn0");

        // {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
        Base64URLValue part2 = new Base64URLValue("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

        PlainJWT jwt = new PlainJWT(part1, part2);

        Assertions.assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);
        Assertions.assertThat(jwt.getHeader().getType()).isNull();
        Assertions.assertThat(jwt.getHeader().getContentType()).isNull();

        JWTClaimsSet cs = jwt.getJWTClaimsSet();

        Assertions.assertThat(cs.getIssuer()).isEqualTo("joe");
        Assertions.assertThat(cs.getExpirationTime()).isEqualTo(new Date(1300819380L * 1000));
        Assertions.assertThat((Boolean) cs.getClaim("http://example.com/is_root")).isTrue();
    }

    @Test
    public void testParse()
            throws Exception {

        String jwtString = "eyJhbGciOiJub25lIn0" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                ".";

        PlainJWT jwt = PlainJWT.parse(jwtString);

        Assertions.assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);
        Assertions.assertThat(jwt.getHeader().getType()).isNull();
        Assertions.assertThat(jwt.getHeader().getContentType()).isNull();

        JWTClaimsSet cs = jwt.getJWTClaimsSet();

        Assertions.assertThat(cs.getIssuer()).isEqualTo("joe");
        Assertions.assertThat(cs.getExpirationTime()).isEqualTo(new Date(1300819380L * 1000));
        Assertions.assertThat((Boolean) cs.getClaim("http://example.com/is_root")).isTrue();
    }

    @Test
    public void testExampleKristina()
            throws Exception {

        String jwtString = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=\n" +
                ".eyJleHAiOjM3NzQ4NjQwNSwiYXpwIjoiRFAwMWd5M1Frd1ZHR2RJZWpJSmdMWEN0UlRnYSIsInN1\n" +
                "YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6IkRQMDFneTNRa3dWR0dkSWVqSUpnTFhDdFJU\n" +
                "Z2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMmVuZHBvaW50c1wvdG9r\n" +
                "ZW4iLCJpYXQiOjM3Mzg4NjQwNX0=\n" +
                ".";

        PlainJWT plainJWT = PlainJWT.parse(jwtString);

        // Header
        Assertions.assertThat(plainJWT.getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);
        Assertions.assertThat(plainJWT.getHeader().getType()).isEqualTo(new JOSEObjectType("JWT"));

        // Claims
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getExpirationTime()).isEqualTo(new Date(377486405L * 1000));
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getClaim("azp")).isEqualTo("DP01gy3QkwVGGdIejIJgLXCtRTga");
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getSubject()).isEqualTo("admin@carbon.super");
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getAudience().get(0)).isEqualTo("DP01gy3QkwVGGdIejIJgLXCtRTga");
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getIssuer()).isEqualTo("https://localhost:9443/oauth2endpoints/token");
        Assertions.assertThat(plainJWT.getJWTClaimsSet().getIssueTime()).isEqualTo(new Date(373886405L * 1000));
    }

    @Test
    public void testTrimWhitespace() {

        PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().build());
        String jwtString = " " + jwt.serialize() + " ";
        Assertions.assertThatCode(
                () -> PlainJWT.parse(jwtString)
        ).doesNotThrowAnyException();
    }

    @Test
    public void testPayloadUpdated()
            throws Exception {

        PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("before").build());

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("before");


        jwt.setPayload(new Payload(new JWTClaimsSet.Builder()
                .subject("after").build().toJSONObject()));

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("after");
    }
}