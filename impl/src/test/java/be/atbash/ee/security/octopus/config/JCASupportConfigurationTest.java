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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class JCASupportConfigurationTest {

    @AfterEach
    public void cleanup() throws NoSuchFieldException {
        TestConfig.resetConfig();
        // Reset the static variable to allow static to be initialized again.
        TestReflectionUtils.resetOf(JCASupportConfiguration.class, "INSTANCE");
    }


    @Test
    void getSecureRandom_default() {
        SecureRandom secureRandom = JCASupportConfiguration.getInstance().getSecureRandom();
        assertThat(secureRandom).isNotNull();
    }

    @Test
    void getSecureRandom_configured() {
        TestConfig.addConfigValue("jwt.jca.securerandom.algo", "NONCEANDIV");

        SecureRandom secureRandom = JCASupportConfiguration.getInstance().getSecureRandom();
        assertThat(secureRandom).isNotNull();
        assertThat(secureRandom.getAlgorithm()).isEqualTo("NONCEANDIV");
    }

    @Test
    void getSecureRandom_invalid() {
        TestConfig.addConfigValue("jwt.jca.securerandom.algo", "xyz");

        ConfigurationException exception = Assertions.assertThrows(ConfigurationException.class, () -> JCASupportConfiguration.getInstance().getSecureRandom());
        assertThat(exception.getMessage()).isEqualTo("no such algorithm: xyz for provider BC");

    }
}