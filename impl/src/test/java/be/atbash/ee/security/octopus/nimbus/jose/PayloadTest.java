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


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import jakarta.json.JsonObject;
import java.nio.charset.StandardCharsets;


/**
 * Tests the JOSE payload class.
 */
class PayloadTest {

    @AfterEach
    public void cleanup() {
        MDC.clear();
    }

    @Test
    void testJWSObject()
            throws Exception {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JWSObject jwsObject = JWSObject.parse(jws);

        Payload payload = new Payload(jwsObject);

        Assertions.assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.JWS_OBJECT);
        Assertions.assertThat(payload.toJWSObject()).isEqualTo(jwsObject);
        Assertions.assertThat(payload).hasToString(jws);
        Assertions.assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }


    @Test
    void testJWSObjectFromString() {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Payload payload = new Payload(jws);

        Assertions.assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.STRING);
        Assertions.assertThat(payload.toJWSObject()).isNotNull();
        Assertions.assertThat(payload.toJWSObject().getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);

        Assertions.assertThat(payload).hasToString(jws);
        Assertions.assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    void testSignedJWT()
            throws Exception {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        SignedJWT signedJWT = SignedJWT.parse(jws);

        Payload payload = new Payload(signedJWT);

        Assertions.assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.SIGNED_JWT);
        Assertions.assertThat(payload.toSignedJWT()).isEqualTo(signedJWT);

        Assertions.assertThat(payload.toJWSObject()).isNotNull();

        Assertions.assertThat(payload).hasToString(jws);
        Assertions.assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    void testSignedJWTFromString()
            throws Exception {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Payload payload = new Payload(jws);

        Assertions.assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.STRING);
        Assertions.assertThat(payload.toJWSObject()).isNotNull();
        Assertions.assertThat(payload.toJWSObject().getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(payload.toSignedJWT().getJWTClaimsSet().getIssuer()).isEqualTo("joe");


        Assertions.assertThat(payload).hasToString(jws);
        Assertions.assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    void testRejectUnsignedJWS() {

        Assertions.assertThatThrownBy(() ->
                        new Payload(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("test"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The JWS object must be signed");
    }

    @Test
    void testRejectUnsignedJWT() {

        Assertions.assertThatThrownBy(() ->
                        new Payload(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The JWT must be signed");

    }

    @Test
    void toJsonObject() {
        Payload payload = new Payload("This is not Json");
        JsonObject jsonObject = payload.toJSONObject();
        Assertions.assertThat(jsonObject).isNull();
        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON))
                .isEqualTo("The payload of the token is not a valid JSON: This is not Json");
    }
}
