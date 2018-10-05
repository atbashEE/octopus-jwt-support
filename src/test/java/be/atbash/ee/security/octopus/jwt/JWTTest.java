/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.jwt;

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SingleKeySelector;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTTest {

    private Payload payload;

    @Before
    public void setup() {
        payload = new Payload();
        payload.setValue("Spock");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

    }

    @Test
    public void encodingNone() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        Payload data = new JWTDecoder().decode(encoded, Payload.class);

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    @Test
    public void encodingJWT_HMAC() {


        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        AtbashKey key = HmacSecretUtil.generateSecretKey("hmacID", secret);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new SingleKeySelector(key);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

}
