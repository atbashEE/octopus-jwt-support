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

import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;


class SignedJWTTest {

    @Test
    void testCustomClaimsAreOrderedByInsertion() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.genKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        JWTClaimsSet claimsSetOne = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(new Date(123000L))
                .issuer("https://c2id.com")
                .claim("scope", "openid")
                .build();

        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetOne);
        signedJWT.sign(signer);
        String orderOne = signedJWT.serialize();

        JWTClaimsSet claimsSetTwo = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .issueTime(new Date(123000L))
                .claim("scope", "openid")
                .build();

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetTwo);
        signedJWT.sign(signer);
        String orderTwo = signedJWT.serialize();
        Assertions.assertThat(orderTwo).isNotEqualTo(orderOne);
    }

    @Test
    void testSignAndVerify()
            throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(new Date(123000L))
                .issuer("https://c2id.com")
                .claim("scope", "openid")
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                keyID("1").
                jwkURL(new URI("https://c2id.com/jwks.json")).
                build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        Assertions.assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.UNSIGNED);
        Assertions.assertThat(signedJWT.getHeader()).isEqualTo(header);
        Assertions.assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        Assertions.assertThat(signedJWT.getJWTClaimsSet().getIssueTime()).isNotNull();
        Assertions.assertThat(signedJWT.getJWTClaimsSet().getIssueTime().getTime()).isEqualTo(123000L);
        Assertions.assertThat(signedJWT.getJWTClaimsSet().getIssuer()).isEqualTo("https://c2id.com");
        Assertions.assertThat(signedJWT.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("openid");

        Assertions.assertThat(signedJWT.getSignature()).isNull();

        Base64URLValue sigInput = Base64URLValue.encode(signedJWT.getSigningInput());

        JWSSigner signer = new RSASSASigner(privateKey);

        signedJWT.sign(signer);

        Assertions.assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        Assertions.assertThat(signedJWT.getSignature()).isNotNull();

        String serializedJWT = signedJWT.serialize();

        signedJWT = SignedJWT.parse(serializedJWT);
        Assertions.assertThat(signedJWT.getParsedString()).isEqualTo(serializedJWT);

        Assertions.assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        Assertions.assertThat(signedJWT.getSignature()).isNotNull();
        Assertions.assertThat(Base64URLValue.encode(signedJWT.getSigningInput())).isEqualTo(sigInput);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        Assertions.assertThat(signedJWT.verify(verifier)).isTrue();
    }


    @Test
    void testTrimWhitespace()
            throws Exception {

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
        jwt.sign(new MACSigner(secret));

        String jwtString = " " + jwt.serialize() + " ";

        jwt = SignedJWT.parse(jwtString);
        Assertions.assertThat(jwt.verify(new MACVerifier(secret))).isTrue();
    }


    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
    @Test
    void testSignedJWTWithNullClaimValue()
            throws Exception {

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .claim("myclaim", null)
                .build();

        JWSObject jwsObject = new JWSObject(
                new JWSHeader(JWSAlgorithm.HS256),
                new Payload(claimsSet.toJSONObject(true))
        );

        jwsObject.sign(new MACSigner(secret));

        SignedJWT jwt = SignedJWT.parse(jwsObject.serialize());
        Assertions.assertThat(jwt.verify(new MACVerifier(secret))).isTrue();

        claimsSet = jwt.getJWTClaimsSet();
        Assertions.assertThat(claimsSet.getSubject()).isEqualTo("alice");
        Assertions.assertThat(claimsSet.getClaim("myclaim")).isNull();

        Assertions.assertThat(claimsSet.getClaims()).containsKey("myclaim");
        Assertions.assertThat(claimsSet.getClaims()).hasSize(2);
    }


    @Test
    void testPayloadUpdated()
            throws Exception {

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .subject("before").build());

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("before");

        jwt.setPayload(new Payload(new JWTClaimsSet.Builder()
                .subject("after").build().toJSONObject()));

        Assertions.assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("after");
    }


    @Test
    void testParseWithExcessiveMixedNestingInPayload() throws ParseException {

        StringBuilder sb = new StringBuilder("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjpb");
        for (int i = 0; i < 1000; i++) {
            sb.append("W1tb");
        }
        sb.append(".aaaa");

        SignedJWT jwt = SignedJWT.parse(sb.toString());

        Assertions.assertThatThrownBy(
                        jwt::getJWTClaimsSet
                ).isInstanceOf(ParseException.class)
                .hasMessage("Payload of JWS object is not a valid JSON object");
    }
}