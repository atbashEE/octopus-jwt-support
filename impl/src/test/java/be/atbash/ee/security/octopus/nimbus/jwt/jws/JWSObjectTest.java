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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JWS object methods.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JWSObjectTest {

    @Test
    public void testBase64URLConstructor()
            throws Exception {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");

        JWSObject jws = new JWSObject(firstPart, secondPart, thirdPart);

        assertThat(jws.getHeader().toBase64URL()).isEqualTo(firstPart);
        assertThat(jws.getPayload().toBase64URL()).isEqualTo(secondPart);
        assertThat(jws.getSignature()).isEqualTo(thirdPart);

        assertThat(jws.serialize()).isEqualTo(firstPart.toString() + ".abc.def");
        assertThat(jws.getParsedString()).isEqualTo(firstPart.toString() + ".abc.def");

        assertThat(jws.getState()).isEqualTo(JWSObject.State.SIGNED);
    }


    @Test
    public void testSignAndSerialize()
            throws Exception {

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

        Base64URLValue signingInput = Base64URLValue.encode(jwsObject.getSigningInput());

        assertThat(Base64URLValue.encode(jwsObject.getSigningInput())).isEqualTo(signingInput);

        jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

        String output = jwsObject.serialize();

        assertThat(jwsObject.serialize()).isEqualTo(output);
    }
}