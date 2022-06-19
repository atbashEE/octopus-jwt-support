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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.text.ParseException;


/**
 * Tests JWS object methods.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
class JWSObjectTest {

    @AfterEach
    public void cleanup() {
        MDC.clear();
    }

    @Test
    void testBase64URLConstructor() throws Exception {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");

        JWSObject jws = new JWSObject(firstPart, secondPart, thirdPart);

        Assertions.assertThat(jws.getHeader().toBase64URL()).isEqualTo(firstPart);
        Assertions.assertThat(jws.getPayload().toBase64URL()).isEqualTo(secondPart);
        Assertions.assertThat(jws.getSignature()).isEqualTo(thirdPart);

        Assertions.assertThat(jws.serialize()).isEqualTo(firstPart.toString() + ".abc.def");
        Assertions.assertThat(jws.getParsedString()).isEqualTo(firstPart + ".abc.def");

        Assertions.assertThat(jws.getState()).isEqualTo(JWSObject.State.SIGNED);
        Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();
    }

    @Test
    public void testBase64URLConstructor_headerNull() {

        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");

        Assertions.assertThatThrownBy(() -> new JWSObject(null, secondPart, thirdPart))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The first part must not be null");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The token has no header");

    }

    @Test
    public void testBase64URLConstructor_headerInvalid() {

        Base64URLValue firstPart = new Base64URLValue("xyz");
        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");

        Assertions.assertThatThrownBy(() -> new JWSObject(firstPart, secondPart, thirdPart))
                .isInstanceOf(ParseException.class)
                .hasMessage("Invalid JWS header: Invalid JSON: Internal error: Unexpected char 65,533 at (line no=1, column no=1, offset=0)");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The token has an invalid header");

    }

    @Test
    public void testBase64URLConstructor_payloadNull() {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue thirdPart = new Base64URLValue("def");

        Assertions.assertThatThrownBy(() -> new JWSObject(firstPart, null, thirdPart))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The second part must not be null");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The token has no payload section");

    }

    @Test
    public void testBase64URLConstructor_signatureNull() {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue secondPart = new Base64URLValue("abc");

        Assertions.assertThatThrownBy(() -> new JWSObject(firstPart, secondPart, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The third part must not be null");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The token has no signature section");

    }

    @Test
    public void testSignAndSerialize() {

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

        Base64URLValue signingInput = Base64URLValue.encode(jwsObject.getSigningInput());

        Assertions.assertThat(Base64URLValue.encode(jwsObject.getSigningInput())).isEqualTo(signingInput);

        jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

        String output = jwsObject.serialize();

        Assertions.assertThat(jwsObject.serialize()).isEqualTo(output);
    }
}