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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import org.junit.Test;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

public class JWKSetCacheTest {

    @Test
    public void testDefaultConstructor() throws InterruptedException {

        JWKSetCache cache = new JWKSetCache();

        assertThat(JWKSetCache.DEFAULT_LIFESPAN_MINUTES).isEqualTo(5);
        assertThat(cache.getLifespan(TimeUnit.MINUTES)).isEqualTo(JWKSetCache.DEFAULT_LIFESPAN_MINUTES);
        assertThat(cache.get()).isNull();
        assertThat(cache.getPutTimestamp()).isEqualTo(-1L);
        assertThat(cache.isExpired()).isFalse();

        JWKSet jwkSet = new JWKSet();

        cache.put(jwkSet);
        Thread.sleep(20);

        assertThat(cache.get()).isEqualTo(jwkSet);
        assertThat(new Date().getTime()).isGreaterThan(cache.getPutTimestamp());
        Thread.sleep(20);

        assertThat(cache.isExpired()).isFalse();

        cache.put(null); // clear
        assertThat(cache.get()).isNull();
        assertThat(cache.isExpired()).isFalse();
    }

    @Test
    public void testParamConstructor() throws InterruptedException {

        JWKSetCache cache = new JWKSetCache(1L, TimeUnit.SECONDS);

        assertThat(cache.getLifespan(TimeUnit.SECONDS)).isEqualTo(1L);
        assertThat(cache.get()).isNull();
        assertThat(cache.getPutTimestamp()).isEqualTo(-1L);
        assertThat(cache.isExpired()).isFalse();

        JWKSet jwkSet = new JWKSet();

        cache.put(jwkSet);
        Thread.sleep(20);

        assertThat(cache.get()).isEqualTo(jwkSet);
        assertThat(new Date().getTime()).isGreaterThan(cache.getPutTimestamp());
        assertThat(cache.isExpired()).isFalse();

        Thread.sleep(2 * 1000L);

        assertThat(cache.get()).isNull();
        assertThat(cache.isExpired()).isTrue();
    }

    @Test
    public void testNoExpiration() throws InterruptedException {

        JWKSetCache cache = new JWKSetCache(-1L, null);

        assertThat(cache.getLifespan(TimeUnit.HOURS)).isEqualTo(-1L);
        assertThat(cache.get()).isNull();
        assertThat(cache.isExpired()).isFalse();
        assertThat(cache.getPutTimestamp()).isEqualTo(-1L);

        JWKSet jwkSet = new JWKSet();

        cache.put(jwkSet);
        Thread.sleep(20);

        assertThat(cache.get()).isEqualTo(jwkSet);
        assertThat(new Date().getTime()).isGreaterThan(cache.getPutTimestamp());
        assertThat(cache.isExpired()).isFalse();
    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/289/clearing-the-jwksetcache-must-undefine-the
    public void testCacheClearMustUndefinePutTimestamp() throws InterruptedException {

        JWKSetCache cache = new JWKSetCache();

        assertThat(cache.get()).isNull();
        assertThat(cache.getPutTimestamp()).isEqualTo(-1L);
        assertThat(cache.getLifespan(TimeUnit.MINUTES)).isEqualTo(JWKSetCache.DEFAULT_LIFESPAN_MINUTES);
        assertThat(cache.isExpired()).isFalse();

        JWKSet jwkSet = new JWKSet();

        cache.put(jwkSet);
        Thread.sleep(20);

        assertThat(cache.getPutTimestamp() > 0).isTrue();
        assertThat(cache.getLifespan(TimeUnit.MINUTES)).isEqualTo(JWKSetCache.DEFAULT_LIFESPAN_MINUTES);
        assertThat(cache.isExpired()).isFalse();

        // clear cache
        cache.put(null);

        assertThat(cache.get()).isNull();
        assertThat(cache.getPutTimestamp()).isEqualTo(-1L);
        assertThat(cache.getLifespan(TimeUnit.MINUTES)).isEqualTo(JWKSetCache.DEFAULT_LIFESPAN_MINUTES);
        assertThat(cache.isExpired()).isFalse();
    }
}