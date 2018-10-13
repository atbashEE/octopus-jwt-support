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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.decoder.JWTData;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.SingleKeySelector;
import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class HmacSecretUtilTest {

    @Test
    public void generateSecretKey() {

        SecureRandom random = new SecureRandom();
        byte[] secret = new byte[32];
        random.nextBytes(secret);

        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("kid", secret);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(atbashKey)
                .build();

        JWTEncoder encoder = new JWTEncoder();
        String encoded = encoder.encode(new SomeToken("Atbash", 123), parameters);

        JWTDecoder decoder = new JWTDecoder();
        JWTData<SomeToken> data = decoder.decode(encoded, SomeToken.class, new SingleKeySelector(atbashKey), null);

        assertThat(data.getData().getStringProperty()).isEqualTo("Atbash");
        assertThat(data.getData().getIntProperty()).isEqualTo(123);

    }

    private static class SomeToken {
        private String stringProperty;
        private int intProperty;

        public SomeToken() {
        }

        public SomeToken(String stringProperty, int intProperty) {
            this.stringProperty = stringProperty;
            this.intProperty = intProperty;
        }

        public String getStringProperty() {
            return stringProperty;
        }

        public void setStringProperty(String stringProperty) {
            this.stringProperty = stringProperty;
        }

        public int getIntProperty() {
            return intProperty;
        }

        public void setIntProperty(int intProperty) {
            this.intProperty = intProperty;
        }
    }
}