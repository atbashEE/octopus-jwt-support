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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Examples verification of draft-ietf-jose-jws-signing-input-options-02
 */
public class UnencodedJWSPayloadTest {

    // From http://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-09#section-4
    private static final String octJWKString = "{" +
            "\"kty\":\"oct\"," +
            "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"" +
            "}";


    private static final OctetSequenceKey JWK;


    static {
        try {
            JWK = OctetSequenceKey.parse(octJWKString);
        } catch (ParseException e) {
            throw new RuntimeException(e.getMessage());
        }
    }


    @Test
    public void testPayloadAsBase64URL() {

        assertThat(new Base64URLValue("JC4wMg").decodeToString()).isEqualTo("$.02");
    }

    @Test
    public void testControlJWS()
            throws Exception {

        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("$.02"));
        jwsObject.sign(new MACSigner(JWK));
        String expected = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
        assertThat(jwsObject.serialize()).isEqualTo(expected);
    }

    @Test
    public void testB64False()
            throws Exception {

        Base64URLValue headerB64 = new Base64URLValue("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19");
        JWSHeader header = JWSHeader.parse(headerB64);
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat((Boolean) header.getCustomParameter("b64")).isFalse();
        Set<String> crit = header.getCriticalParams();
        assertThat(crit.contains("b64")).isTrue();
        assertThat(crit).hasSize(1);
        assertThat(header.toJSONObject().build()).hasSize(3);

        JWSSigner signer = new MACSigner(JWK);

        byte[] headerBytes = (header.toBase64URL().toString() + '.').getBytes(StandardCharsets.UTF_8);
        byte[] payloadBytes = "$.02".getBytes(StandardCharsets.UTF_8);
        byte[] signingInput = new byte[headerBytes.length + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);

        Base64URLValue signature = signer.sign(header, signingInput);
        Base64URLValue expectedSignature = new Base64URLValue("A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY");
        assertThat(signature).isEqualTo(expectedSignature);

        JWSVerifier verifier = new MACVerifier(JWK, new HashSet<>(Collections.singletonList("b64")));
        assertThat(verifier.verify(header, signingInput, signature)).isTrue();
    }

    @Test
    public void testNonBase64EncodedClaimsSet()
            throws Exception {
        //Given

        //Create JWT

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .parameter("b64", false)
                .build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("foo", "bar")
                .build();

        //When sign JWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new MACSigner(JWK);
        signedJWT.sign(signer);
        String serializedJWT = signedJWT.serialize(true);
        signedJWT = SignedJWT.parse(serializedJWT);

        //Then
        assertThat((Boolean) header.getCustomParameter("b64")).isFalse();

        JWSVerifier verifier = new MACVerifier(JWK, new HashSet<>(Collections.singletonList("b64")));
        byte[] payloadBytes = claimsSet.toString().getBytes(StandardCharsets.UTF_8);
        byte[] headerBytes = (header.toBase64URL().toString() + '.').getBytes(StandardCharsets.UTF_8);
        byte[] signingInput = new byte[headerBytes.length + payloadBytes.length];
        System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
        System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);

        assertThat(verifier.verify(header, signingInput, signedJWT.getSignature())).isTrue();
    }
}
