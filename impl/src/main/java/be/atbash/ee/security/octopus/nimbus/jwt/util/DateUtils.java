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
package be.atbash.ee.security.octopus.nimbus.jwt.util;


import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;


/**
 * Date utilities.
 */
public class DateUtils {


    /**
     * Converts the specified date object to a Unix epoch time in seconds.
     *
     * @param date The date. Must not be {@code null}.
     * @return The Unix epoch time, in seconds.
     */
    public static long toSecondsSinceEpoch(Date date) {

        return date.getTime() / 1000L;
    }

    /**
     * Converts the specified date object to a Unix epoch time in seconds.
     *
     * @param date The date. Must not be {@code null}.
     * @return The Unix epoch time, in seconds.
     */
    public static long toSecondsSinceEpoch(LocalDateTime date) {

        return date.toEpochSecond(ZoneOffset.UTC);
    }

    /**
     * Converts the specified Unix epoch time in seconds to a date object.
     *
     * @param time The Unix epoch time, in seconds. Must not be negative.
     * @return The date.
     */
    public static Date fromSecondsSinceEpoch(long time) {

        return new Date(time * 1000L);
    }


    /**
     * Check if the specified date is after the specified reference, given
     * the maximum accepted negative clock skew.
     *
     * <p>Formula:
     *
     * <pre>
     * return date + clock_skew &gt; reference
     * </pre>
     * <p>
     * Example: Ensure a JWT expiration (exp) timestamp is after the
     * current time, with a minute of acceptable clock skew.
     *
     * <pre>
     * boolean valid = DateUtils.isAfter(exp, new Date(), 60);
     * </pre>
     *
     * @param date                The date to check. Must not be
     *                            {@code null}.
     * @param reference           The reference date (e.g. the current
     *                            time). Must not be {@code null}.
     * @param maxClockSkewSeconds The maximum acceptable negative clock
     *                            skew of the date value to check, in
     *                            seconds.
     * @return {@code true} if the date is before the reference, plus the
     * maximum accepted clock skew, else {@code false}.
     */
    public static boolean isAfter(Date date,
                                  Date reference,
                                  int maxClockSkewSeconds) {
        // TODO As Java 8 features
        return new Date(date.getTime() + maxClockSkewSeconds * 1000L).after(reference);
    }


    /**
     * Checks if the specified date is before the specified reference,
     * given the maximum accepted positive clock skew.
     *
     * <p>Formula:
     *
     * <pre>
     * return date - clock_skew &lt; reference
     * </pre>
     * <p>
     * Example: Ensure a JWT issued-at (iat) timestamp is before the
     * current time, with a minute of acceptable clock skew.
     *
     * <pre>
     * boolean valid = DateUtils.isBefore(iat, new Date(), 60);
     * </pre>
     *
     * @param date                The date to check. Must not be
     *                            {@code null}.
     * @param reference           The reference date (e.g. the current
     *                            time). Must not be {@code null}.
     * @param maxClockSkewSeconds The maximum acceptable clock skew of the
     *                            date value to check, in seconds.
     * @return {@code true} if the date is before the reference, minus the
     * maximum accepted clock skew, else {@code false}.
     */
    public static boolean isBefore(Date date,
                                   Date reference,
                                   int maxClockSkewSeconds) {
        // TODO As Java 8 features
        return new Date(date.getTime() - maxClockSkewSeconds * 1000L).before(reference);
    }


    /**
     * Prevents instantiation.
     */
    private DateUtils() {
    }
}
