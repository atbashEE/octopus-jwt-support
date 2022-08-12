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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest {


    @Test
    public void testToSeconds() {

        Date date = new Date(2000L);

        Assertions.assertThat(DateUtils.toSecondsSinceEpoch(date)).isEqualTo(2);
    }

    @Test
    public void testToSecondsFromLocalDate() {

        LocalDateTime date = LocalDateTime.of(1970, 1, 1, 7, 15);
        // (7*60+15) -> min * 60 -> sec

        Assertions.assertThat(DateUtils.toSecondsSinceEpoch(date)).isEqualTo(26100);
    }

    @Test
    public void testFromSeconds() {

        Assertions.assertThat(DateUtils.fromSecondsSinceEpoch(2)).isEqualTo(new Date(2000L));
    }

    @Test
    public void testRoundTrip() {

        Date date = new Date(100000);

        long ts = DateUtils.toSecondsSinceEpoch(date);

        Assertions.assertThat(date).isEqualTo(DateUtils.fromSecondsSinceEpoch(ts));
    }

    @Test
    public void testAfterNoClockSkew_true() {

        Date date = new Date(100001L);
        Date reference = new Date(100000L);
        Assertions.assertThat(DateUtils.isAfter(date, reference, 0)).isTrue();
    }

    @Test
    public void testAfterNoClockSkew_false() {

        Date date = new Date(100000L);
        Date reference = new Date(100001L);
        Assertions.assertThat(DateUtils.isAfter(date, reference, 0)).isFalse();
    }

    @Test
    public void testBeforeNoClockSkew_true() {

        Date date = new Date(100000L);
        Date reference = new Date(100001L);
        Assertions.assertThat(DateUtils.isBefore(date, reference, 0)).isTrue();
    }

    @Test
    public void testBeforeNoClockSkew_false() {

        Date date = new Date(100001L);
        Date reference = new Date(100000L);
        Assertions.assertThat(DateUtils.isBefore(date, reference, 0)).isFalse();
    }

    @Test
    public void testAfterWithClockSkew_true() {

        Date date = new Date(2000L);
        Date reference = new Date(2999L);
        int skewSeconds = 1;
        Assertions.assertThat(DateUtils.isAfter(date, reference, skewSeconds)).isTrue();
    }

    @Test
    public void testAfterWithClockSkew_false() {

        Date date = new Date(2000L);
        Date reference = new Date(3000L);
        int skewSeconds = 1;
        Assertions.assertThat(DateUtils.isAfter(date, reference, skewSeconds)).isFalse();
    }

    @Test
    public void testBeforeWithClockSkew_true() {

        Date date = new Date(2000L);
        Date reference = new Date(1001L);
        int skewSeconds = 1;
        Assertions.assertThat(DateUtils.isBefore(date, reference, skewSeconds)).isTrue();
    }

    @Test
    public void testBeforeWithClockSkew_false() {

        Date date = new Date(2000L);
        Date reference = new Date(1000L);
        int skewSeconds = 1;
        Assertions.assertThat(DateUtils.isBefore(date, reference, skewSeconds)).isFalse();
    }

    @Test
    public void testNotBefore() {

        int skewSeconds = 1;

        Assertions.assertThat(DateUtils.isAfter(new Date(4001L), new Date(5000L), skewSeconds)).isTrue();
        Assertions.assertThat(DateUtils.isAfter(new Date(5000L), new Date(5000L), skewSeconds)).isTrue();
        Assertions.assertThat(DateUtils.isAfter(new Date(6000L), new Date(5000L), skewSeconds)).isTrue();
        Assertions.assertThat(DateUtils.isAfter(new Date(4000L), new Date(5000L), skewSeconds)).isFalse();
    }

    @Test
    public void testForEXPClaim() {

        Date now = new Date();

        Date exp = new Date(now.getTime() - 30 * 1000L); // 30 seconds behind

        boolean valid = DateUtils.isAfter(exp, now, 60);
        Assertions.assertThat(valid).isTrue();
    }

    @Test
    public void testForIATClaim() {

        Date now = new Date();

        Date iat = new Date(now.getTime() + 30 * 1000L); // 30 seconds ahead

        boolean valid = DateUtils.isBefore(iat, now, 60);
        Assertions.assertThat(valid).isTrue();
    }

    @Test
    public void testAsDateAsLocalDate() {
        LocalDateTime original = LocalDateTime.now();
        LocalDateTime converted = DateUtils.asLocalDateTime(DateUtils.asDate(original));
        Assertions.assertThat(converted).isCloseTo(original, Assertions.within(100, ChronoUnit.MILLIS));
    }

    @Test
    public void testAsLocalDateAsDate() {
        Date original = new Date();
        Date converted = DateUtils.asDate(DateUtils.asLocalDateTime(original));
        Assertions.assertThat(converted).isEqualTo(original);
    }

    @Test
    public void testWithin() {

        Date now = new Date();

        Date ref = now;

        Assertions.assertThat(DateUtils.isWithin(now, ref, 1)).isTrue();
        Assertions.assertThat(DateUtils.isWithin(now, ref, 10)).isTrue();
        Assertions.assertThat(DateUtils.isWithin(now, ref, 100)).isTrue();
    }

    @Test
    public void testWithinEdges() {

        Date now = new Date();

        Date ref = now;

        Date nineSecondsAgo = new Date(now.getTime() - 9_000);
        Date nineSecondsAhead = new Date(now.getTime() + 9_000);

        Assertions.assertThat(DateUtils.isWithin(nineSecondsAgo, ref, 10)).isTrue();
        Assertions.assertThat(DateUtils.isWithin(nineSecondsAhead, ref, 10)).isTrue();
    }

    @Test
    public void testWithinNegative() {

        Date now = new Date();

        Date ref = now;

        Date tenSecondsAgo = new Date(now.getTime() - 10_000);
        Date tenSecondsAhead = new Date(now.getTime() + 10_000);

        Assertions.assertThat(DateUtils.isWithin(tenSecondsAgo, ref, 9)).isFalse();
        Assertions.assertThat(DateUtils.isWithin(tenSecondsAhead, ref, 9)).isFalse();
    }
}
