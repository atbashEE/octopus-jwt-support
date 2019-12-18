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

import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class RemoteKeyManagerTest {

    private RemoteKeyManager remoteKeyManager = new RemoteKeyManager();

    @Before
    public void setUp() {
        Jadler.initJadler();
    }


    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void retrieveKeys_remoteSet() {
        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("remoteKid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(set.toJSONObject().toString());

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("remoteKid").withJKU(URI.create("http://localhost:" + Jadler.port() + "/c2id/jwks.json")).build();

        List<AtbashKey> keys = remoteKeyManager.retrieveKeys(criteria);
        assertThat(keys).hasSize(1);
    }

    private RSAPublicKey generateRSAKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("something")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> atbashKeys = generator.generateKeys(generationParameters);
        RSAPublicKey result = null;
        for (AtbashKey atbashKey : atbashKeys) {
            if (atbashKey.getKey() instanceof RSAPublicKey) {
                result = (RSAPublicKey) atbashKey.getKey();
            }
        }
        return result;
    }
}