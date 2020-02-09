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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the critical parameters checker.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class CriticalHeaderParamsDeferralTest {

    @Test
    public void testConstructor() {

        CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

        assertThat(checker.getProcessedCriticalHeaderParams()).isEmpty();
        assertThat(checker.getDeferredCriticalHeaderParams()).isEmpty();
    }

    @Test
    public void testSetter() {

        CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

        checker.setDeferredCriticalHeaderParams(new HashSet<>(Arrays.asList("exp", "hs")));

        assertThat(checker.getDeferredCriticalHeaderParams()).contains("exp");
        assertThat(checker.getDeferredCriticalHeaderParams()).contains("hs");
        assertThat(checker.getDeferredCriticalHeaderParams()).hasSize(2);
    }

    @Test
    public void testPassMissingCritHeader() {

        CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build();

        assertThat(checker.headerPasses(header)).isTrue();
    }

    @Test
    public void testPassIgnoredCritParams() {

        CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();
        checker.setDeferredCriticalHeaderParams(new HashSet<>(Collections.singletonList("exp")));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                keyID("1").
                parameter("exp", "2014-04-24").
                criticalParams(new HashSet<>(Collections.singletonList("exp"))).
                build();

        assertThat(checker.headerPasses(header)).isTrue();
    }

    @Test
    public void testReject() {

        CriticalHeaderParamsDeferral checker = new CriticalHeaderParamsDeferral();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                keyID("1").
                parameter("exp", "2014-04-24").
                criticalParams(new HashSet<>(Collections.singletonList("exp"))).
                build();

        assertThat(checker.headerPasses(header)).isFalse();
    }
}
