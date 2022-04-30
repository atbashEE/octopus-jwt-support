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
package be.atbash.ee.security.octopus.keys;


import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.util.PeriodUtil;

import java.util.Date;
import java.util.concurrent.TimeUnit;


/**
 * JSON Web Key (JWK) set cache implementation.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JWKSetCache {

    /**
     * The lifespan the cached JWK set, in milliseconds.
     */
    private final long lifespan;


    /**
     * The cache put timestamp, negative if not specified.
     */
    private long putTimestamp = -1;


    /**
     * Creates a new JWK set, the default lifespan of the cached JWK set is
     * set to 5 minutes.
     */
    public JWKSetCache() {

        this.lifespan = PeriodUtil.defineSecondsInPeriod(JwtSupportConfiguration.getInstance().getJWKSetCachePeriod()) * 1000L;
    }


    /**
     * The cached JWK set, {@code null} if none.
     */
    private JWKSet jwkSet;


    public void put(JWKSet jwkSet) {

        this.jwkSet = jwkSet;

        if (jwkSet != null) {
            putTimestamp = new Date().getTime();
        } else {
            // cache cleared
            putTimestamp = -1;
        }
    }


    public JWKSet get() {

        if (isExpired()) {
            jwkSet = null; // clear
        }

        return jwkSet;
    }


    /**
     * Returns the cache put timestamp.
     *
     * @return The cache put timestamp, negative if not specified.
     */
    public long getPutTimestamp() {

        return putTimestamp;
    }


    /**
     * Returns {@code true} if the cached JWK set is expired.
     *
     * @return {@code true} if expired.
     */
    public boolean isExpired() {

        return putTimestamp > -1 &&
                new Date().getTime() > putTimestamp + lifespan;
    }


    /**
     * Returns the configured lifespan of the cached JWK.
     *
     * @param timeUnit The time unit to use.
     * @return The configured lifespan, negative means no expiration.
     */
    public long getLifespan(TimeUnit timeUnit) {

        return timeUnit.convert(lifespan, TimeUnit.MILLISECONDS);
    }
}
