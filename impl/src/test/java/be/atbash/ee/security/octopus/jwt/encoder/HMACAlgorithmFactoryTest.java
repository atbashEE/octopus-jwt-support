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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class HMACAlgorithmFactoryTest {

    private HMACAlgorithmFactory factory = new HMACAlgorithmFactory();

    @Test
    public void determineOptimalAlgorithm_short() {
        byte[] secret = defineSecret(256 / 8 + 1);

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        Assertions.assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void determineOptimalAlgorithm_medium() {
        byte[] secret = defineSecret(384 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        Assertions.assertThat(algorithm).isEqualTo(JWSAlgorithm.HS384);
    }

    @Test
    public void determineOptimalAlgorithm_long() {

        byte[] secret = defineSecret(512 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();


        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        Assertions.assertThat(algorithm).isEqualTo(JWSAlgorithm.HS512);
    }

    @Test
    public void tooShort() {

        byte[] secret = defineSecret(184 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();
        Assertions.assertThatThrownBy(() -> {
            factory.determineOptimalAlgorithm(secret);
        }).isInstanceOf(ConfigurationException.class);

    }

    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        return bytes;
    }


}