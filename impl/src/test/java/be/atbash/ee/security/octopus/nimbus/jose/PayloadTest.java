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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JOSE payload class.
 */
public class PayloadTest {

    @Test
    public void testJWSObject()
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

        assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.JWS_OBJECT);
        assertThat(payload.toJWSObject()).isEqualTo(jwsObject);
        assertThat(payload.toString()).isEqualTo(jws);
        assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }


    @Test
    public void testJWSObjectFromString() {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Payload payload = new Payload(jws);

        assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.STRING);
        assertThat(payload.toJWSObject()).isNotNull();
        assertThat(payload.toJWSObject().getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);

        assertThat(payload.toString()).isEqualTo(jws);
        assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    public void testSignedJWT()
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

        assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.SIGNED_JWT);
        assertThat(payload.toSignedJWT()).isEqualTo(signedJWT);

        assertThat(payload.toJWSObject()).isNotNull();

        assertThat(payload.toString()).isEqualTo(jws);
        assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    public void testSignedJWTFromString()
            throws Exception {

        // From http://tools.ietf.org/html/rfc7515#appendix-A.1
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Payload payload = new Payload(jws);

        assertThat(payload.getOrigin()).isEqualTo(Payload.Origin.STRING);
        assertThat(payload.toJWSObject()).isNotNull();
        assertThat(payload.toJWSObject().getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(payload.toSignedJWT().getJWTClaimsSet().getIssuer()).isEqualTo("joe");

        assertThat(payload.toJWSObject()).isNotNull();

        assertThat(payload.toString()).isEqualTo(jws);
        assertThat(new String(payload.toBytes(), StandardCharsets.UTF_8)).isEqualTo(jws);
    }

    @Test
    public void testRejectUnsignedJWS() {

        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new Payload(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("test"))));

        assertThat(e.getMessage()).isEqualTo("The JWS object must be signed");

    }

    @Test
    public void testRejectUnsignedJWT() {

        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> new Payload(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build())));

        assertThat(e.getMessage()).isEqualTo("The JWT must be signed");

    }

}
