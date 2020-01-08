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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultJWTClaimsVerifierTest {

    private TestLogger logger = TestLoggerFactory.getTestLogger(DefaultJWTClaimsVerifier.class);

    @AfterEach
    public void tearDown() {
        logger.clear();
        TestConfig.resetConfig();
    }


    @Test
    public void testDefaultConstructor() throws NoSuchFieldException {

        DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
        assertThat((Set) TestReflectionUtils.getValueOf(verifier, "acceptedAudienceValues")).isNull();
        assertThat(((JWTClaimsSet) TestReflectionUtils.getValueOf(verifier, "exactMatchClaims")).getClaims()).isEmpty();
        assertThat((Set) TestReflectionUtils.getValueOf(verifier, "requiredClaims")).isEmpty();
        assertThat((Set) TestReflectionUtils.getValueOf(verifier, "prohibitedClaims")).isEmpty();
        assertThat((Integer) TestReflectionUtils.getValueOf(verifier, "maxClockSkew")).isEqualTo(60);

    }

    @Test
    public void testValidNoClaims() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testNotExpired() {

        Date now = new Date();
        Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(tomorrow)
                .build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testExpired() {

        Date now = new Date();
        Date yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(yesterday)
                .build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("Expired JWT");

    }

    @Test
    public void testNbfAccepted() {

        Date now = new Date();
        Date yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .notBeforeTime(yesterday)
                .build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testNbfDenied() {

        Date now = new Date();
        Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .notBeforeTime(tomorrow)
                .build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT before use time");

    }

    @Test
    public void testAllAccepted() {

        Date now = new Date();
        Date yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(tomorrow)
                .notBeforeTime(yesterday)
                .build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }


    @Test
    public void testExpirationWithClockSkew() {

        Date now = new Date();

        Date thirtySecondsAgo = new Date(now.getTime() - 30 * 1000L);

        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().expirationTime(thirtySecondsAgo).build();
        boolean valid = verifier.verify(null, claimSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testNotBeforeWithClockSkew() {

        Date now = new Date();

        Date thirtySecondsAhead = new Date(now.getTime() + 30 * 1000L);

        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().notBeforeTime(thirtySecondsAhead).build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();

        boolean valid = verifier.verify(null, claimSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

    }

    @Test
    public void testClockSkew() throws NoSuchFieldException {
        TestConfig.addConfigValue("jwt.clock.skew.secs", "120");

        DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

        assertThat((Integer) TestReflectionUtils.getValueOf(verifier, "maxClockSkew")).isEqualTo(120);
    }

    @Test
    public void testIssuer() {

        String iss = "https://c2id.com";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(
                null,
                new JWTClaimsSet.Builder().issuer(iss).build(),
                null);

        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(iss).build();
        boolean data = verifier.verify(null, claimSet);
        assertThat(data).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testIssuerMissing() {

        String iss = "https://c2id.com";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(
                null,
                new JWTClaimsSet.Builder().issuer(iss).build(),
                null);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required claims: [iss]");

    }

    @Test
    public void testIssuerRejected() {

        String iss = "https://c2id.com";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(
                null,
                new JWTClaimsSet.Builder().issuer(iss).build(),
                null);


        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer("https://example.com").build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT \"iss\" claim doesn't match expected value: https://example.com");

    }

    @Test
    public void testAudienceAcceptSetOrNull() {

        String aud = "123";
        HashSet<String> acceptedAudience = new HashSet<>(Arrays.asList(aud, null));
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(acceptedAudience, null, null, null);


        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        claimsSet = new JWTClaimsSet.Builder().audience(aud).build();
        valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        claimsSet = new JWTClaimsSet.Builder().audience(Arrays.asList(aud, "456")).build();
        valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        claimsSet = new JWTClaimsSet.Builder().audience("456").build();
        valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT audience rejected: [456]");

    }

    @Test
    public void testAudienceViaExactMatch() {

        String aud = "123";
        JWTClaimsSet expectedClaims = new JWTClaimsSet.Builder().audience(aud).build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(null, expectedClaims, null, null);


        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience(aud).build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        claimsSet = new JWTClaimsSet.Builder().build();
        valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required claims: [aud]");


        claimsSet = new JWTClaimsSet.Builder().audience("456").build();
        valid = verifier.verify(null, claimsSet);

        assertThat(valid).isFalse();
        loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(1).getMessage()).isEqualTo("JWT \"aud\" claim doesn't match expected value: [456]");
    }

    @Test
    public void testAudienceMissing() {

        String aud = "123";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);


        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        boolean valid = verifier.verify(null, claimsSet);

        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required audience");

    }

    @Test
    public void testAudienceRejected() {

        String aud = "123";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience("456").build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT audience rejected: [456]");
    }

    @Test
    public void testAudienceRejected_multi() {

        String aud = "123";
        JWTVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);


        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience(Arrays.asList("456", "789")).build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT audience rejected: [456, 789]");
    }

    @Test
    public void testProhibitedClaims() {

        JWTVerifier verifier = new DefaultJWTClaimsVerifier(null, null, null, Collections.singleton("scope"));

        boolean valid = verifier.verify(null, new JWTClaimsSet.Builder().build());
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        valid = verifier.verify(null, new JWTClaimsSet.Builder().subject("alice").build());
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("scope", "openid").build();
        valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT has prohibited claims: [scope]");
    }

    @Test
    public void testRequiresIAT() {

        JWTVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("iat"));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issueTime(new Date()).build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        valid = verifier.verify(null, new JWTClaimsSet.Builder().build());
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required claims: [iat]");

    }

    @Test
    public void testRequiresEXP() {

        JWTVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("exp"));

        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().expirationTime(new Date()).build();
        boolean valid = verifier.verify(null, claimSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        valid = verifier.verify(null, new JWTClaimsSet.Builder().build());

        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required claims: [exp]");

    }

    @Test
    public void testRequiresNBF() {

        JWTVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("nbf"));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().notBeforeTime(new Date()).build();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();

        valid = verifier.verify(null, new JWTClaimsSet.Builder().build());
        assertThat(valid).isFalse();
        List<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        assertThat(loggingEvents.get(0).getMessage()).isEqualTo("JWT missing required claims: [nbf]");

    }
}