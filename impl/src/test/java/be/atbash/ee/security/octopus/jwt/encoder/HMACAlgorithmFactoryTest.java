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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.nimbus.jose.JWSAlgorithm;
import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class HMACAlgorithmFactoryTest {

    private HMACAlgorithmFactory factory = new HMACAlgorithmFactory();

    @Test
    public void determineOptimalAlgorithm_short() {
        byte[] secret = defineSecret(256 / 8 + 1);

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void determineOptimalAlgorithm_medium() {
        byte[] secret = defineSecret(384 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();

        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS384);
    }

    @Test
    public void determineOptimalAlgorithm_long() {

        byte[] secret = defineSecret(512 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();


        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret);

        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS512);
    }

    @Test(expected = ConfigurationException.class)
    public void tooShort() {

        byte[] secret = defineSecret(184 / 8 + 1);
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory();

        factory.determineOptimalAlgorithm(secret);

    }

    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        return bytes;
    }


}