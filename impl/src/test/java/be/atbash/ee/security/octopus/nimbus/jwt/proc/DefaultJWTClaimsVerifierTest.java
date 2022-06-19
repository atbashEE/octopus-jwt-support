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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultJWTClaimsVerifierTest {

    @AfterEach
    public void tearDown() {
        MDC.clear();
        TestConfig.resetConfig();
    }


    @Test
    public void testDefaultConstructor() throws NoSuchFieldException {

        DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
        assertThat((Integer) TestReflectionUtils.getValueOf(verifier, "maxClockSkew")).isEqualTo(60);

    }

    @Test
    public void testValidNoClaims() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(MDC.getCopyOfContextMap()).isEmpty();
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
        assertThat(MDC.getCopyOfContextMap()).isEmpty();
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

        String message = MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON);
        assertThat(message).startsWith("The token was expired (exp = ");

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
        assertThat(MDC.getCopyOfContextMap()).isEmpty();
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

        String message = MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON);
        assertThat(message).startsWith("The token should not be used (nbf = ");

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
        assertThat(MDC.getCopyOfContextMap()).isEmpty();
    }


    @Test
    public void testExpirationWithClockSkew() {

        Date now = new Date();

        Date thirtySecondsAgo = new Date(now.getTime() - 30 * 1000L);

        JWTVerifier verifier = new DefaultJWTClaimsVerifier();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().expirationTime(thirtySecondsAgo).build();
        boolean valid = verifier.verify(null, claimSet);
        assertThat(valid).isTrue();
        assertThat(MDC.getCopyOfContextMap()).isEmpty();
    }

    @Test
    public void testNotBeforeWithClockSkew() {

        Date now = new Date();

        Date thirtySecondsAhead = new Date(now.getTime() + 30 * 1000L);

        JWTClaimsSet claimSet = new JWTClaimsSet.Builder().notBeforeTime(thirtySecondsAhead).build();
        JWTVerifier verifier = new DefaultJWTClaimsVerifier();

        boolean valid = verifier.verify(null, claimSet);
        assertThat(valid).isTrue();
        assertThat(MDC.getCopyOfContextMap()).isEmpty();

    }

    @Test
    public void testClockSkew() throws NoSuchFieldException {
        TestConfig.addConfigValue("jwt.clock.skew.secs", "120");

        DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

        assertThat((Integer) TestReflectionUtils.getValueOf(verifier, "maxClockSkew")).isEqualTo(120);
    }

}