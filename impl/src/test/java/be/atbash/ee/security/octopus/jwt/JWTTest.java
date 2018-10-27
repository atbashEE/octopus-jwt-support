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
import be.atbash.util.base64.Base64Codec;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This in one of the high level test for testing complete process end to end.
 * Focusing on no wrapping in JWT, or using signed JWT
 */
public class JWTTest {

    private Payload payload;

    @Before
    public void setup() {
        payload = new Payload();
        payload.setValue("JUnit");
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

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_HMAC_WrongKey() {

        SecureRandom random = new SecureRandom();

        byte[] secret1 = new byte[32];
        random.nextBytes(secret1);
        byte[] secret2 = new byte[32];
        random.nextBytes(secret2);

        AtbashKey key1 = HmacSecretUtil.generateSecretKey("hmacID", secret1);
        AtbashKey key2 = HmacSecretUtil.generateSecretKey("hmacID", secret2);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key1)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new SingleKeySelector(key2);
        new JWTDecoder().decode(encoded, Payload.class, keySelector, null);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_TamperedPayload() {

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        AtbashKey key = HmacSecretUtil.generateSecretKey("hmacID", secret);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        String[] jwtParts = encoded.split("\\.");
        String content = new String(Base64Codec.decode(jwtParts[1]));
        String updatedContent = content.replaceAll("JUnit", "Spock");
        jwtParts[1] = Base64Codec.encodeToString(updatedContent.getBytes(StandardCharsets.UTF_8), false);

        String updatedEncoded = jwtParts[0] + '.' + jwtParts[1] + '.' + jwtParts[2];

        KeySelector keySelector = new SingleKeySelector(key);
        new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector, null);
    }
    // Using a RSA key.
}
