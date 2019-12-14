/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.junit.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest {


    @Test
    public void testToSeconds() {

        Date date = new Date(2000L);

        assertThat(DateUtils.toSecondsSinceEpoch(date)).isEqualTo(2);
    }

    @Test
    public void testFromSeconds() {

        assertThat(DateUtils.fromSecondsSinceEpoch(2)).isEqualTo(new Date(2000L));
    }

    @Test
    public void testRoundTrip() {

        Date date = new Date(100000);

        long ts = DateUtils.toSecondsSinceEpoch(date);

        assertThat(date).isEqualTo(DateUtils.fromSecondsSinceEpoch(ts));
    }

    @Test
    public void testAfterNoClockSkew_true() {

        Date date = new Date(100001L);
        Date reference = new Date(100000L);
        assertThat(DateUtils.isAfter(date, reference, 0)).isTrue();
    }

    @Test
    public void testAfterNoClockSkew_false() {

        Date date = new Date(100000L);
        Date reference = new Date(100001L);
        assertThat(DateUtils.isAfter(date, reference, 0)).isFalse();
    }

    @Test
    public void testBeforeNoClockSkew_true() {

        Date date = new Date(100000L);
        Date reference = new Date(100001L);
        assertThat(DateUtils.isBefore(date, reference, 0)).isTrue();
    }

    @Test
    public void testBeforeNoClockSkew_false() {

        Date date = new Date(100001L);
        Date reference = new Date(100000L);
        assertThat(DateUtils.isBefore(date, reference, 0)).isFalse();
    }

    @Test
    public void testAfterWithClockSkew_true() {

        Date date = new Date(2000L);
        Date reference = new Date(2999L);
        int skewSeconds = 1;
        assertThat(DateUtils.isAfter(date, reference, skewSeconds)).isTrue();
    }

    @Test
    public void testAfterWithClockSkew_false() {

        Date date = new Date(2000L);
        Date reference = new Date(3000L);
        int skewSeconds = 1;
        assertThat(DateUtils.isAfter(date, reference, skewSeconds)).isFalse();
    }

    @Test
    public void testBeforeWithClockSkew_true() {

        Date date = new Date(2000L);
        Date reference = new Date(1001L);
        int skewSeconds = 1;
        assertThat(DateUtils.isBefore(date, reference, skewSeconds)).isTrue();
    }

    @Test
    public void testBeforeWithClockSkew_false() {

        Date date = new Date(2000L);
        Date reference = new Date(1000L);
        int skewSeconds = 1;
        assertThat(DateUtils.isBefore(date, reference, skewSeconds)).isFalse();
    }

    @Test
    public void testNotBefore() {

        int skewSeconds = 1;

        assertThat(DateUtils.isAfter(new Date(4001L), new Date(5000L), skewSeconds)).isTrue();
        assertThat(DateUtils.isAfter(new Date(5000L), new Date(5000L), skewSeconds)).isTrue();
        assertThat(DateUtils.isAfter(new Date(6000L), new Date(5000L), skewSeconds)).isTrue();
        assertThat(DateUtils.isAfter(new Date(4000L), new Date(5000L), skewSeconds)).isFalse();
    }

    @Test
    public void testForEXPClaim() {

        Date now = new Date();

        Date exp = new Date(now.getTime() - 30 * 1000L); // 30 seconds behind

        boolean valid = DateUtils.isAfter(exp, now, 60);
        assertThat(valid).isTrue();
    }

    @Test
    public void testForIATClaim() {

        Date now = new Date();

        Date iat = new Date(now.getTime() + 30 * 1000L); // 30 seconds ahead

        boolean valid = DateUtils.isBefore(iat, now, 60);
        assertThat(valid).isTrue();
    }
}
