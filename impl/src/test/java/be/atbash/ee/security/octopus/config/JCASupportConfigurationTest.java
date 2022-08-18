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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
import be.atbash.util.TestReflectionUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;

import java.security.SecureRandom;
import java.util.List;
import java.util.TimerTask;
import java.util.stream.Collectors;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
// Difficult to clean up TimerTask and Thread that goes with it. So execute test methods in certain order.
class JCASupportConfigurationTest {

    static boolean useProvider = false;

    @AfterEach
    public void cleanup() throws NoSuchFieldException {
        TestConfig.resetConfig();

        // Stop the Task; but this doesn't mean the Thread is immediately gone. Not even when we do Thread.sleep for a while.
        Object task = TestReflectionUtils.getValueOf(JCASupportConfiguration.getInstance(), "task");
        if (task != null) {
            TimerTask timerTask = (TimerTask) task;
            timerTask.cancel();
        }

        // Reset the static variable to allow static to be initialized again.
        TestReflectionUtils.resetOf(JCASupportConfiguration.class, "INSTANCE");

        useProvider = false;
    }


    @Test
    @Order(1)
    void getSecureRandom_default() {
        SecureRandom secureRandom = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom).isNotNull();

        // Check if by default no task is created to recreate SecureRandom
        List<String> threadNames = Thread.getAllStackTraces().keySet()
                .stream()
                .map(Thread::getName)
                .collect(Collectors.toList());
        Assertions.assertThat(threadNames).isNotEmpty();
        Assertions.assertThat(threadNames).doesNotContain("Task to recreate SecureRandom");

    }

    @Test
    @Order(2)
    void getSecureRandom_configured() {
        TestConfig.addConfigValue("jwt.jca.securerandom.algo", "NONCEANDIV");

        SecureRandom secureRandom = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom).isNotNull();
        Assertions.assertThat(secureRandom.getAlgorithm()).isEqualTo("NONCEANDIV");
    }

    @Test
    @Order(3)
    void getSecureRandom_invalid() {
        TestConfig.addConfigValue("jwt.jca.securerandom.algo", "xyz");

        Assertions.assertThatThrownBy(() -> JCASupportConfiguration.getInstance().getSecureRandom())
                .isInstanceOf(ConfigurationException.class)
                .hasMessage("no such algorithm: xyz for provider BC");

    }

    @Test
    @Order(4)
    void getSecureRandom_recreate() throws InterruptedException {
        // 1 second recreate
        TestConfig.addConfigValue("jwt.jca.securerandom.recreate", "1");

        SecureRandom secureRandom1 = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom1).isNotNull();

        SecureRandom secureRandom2 = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom2).isSameAs(secureRandom1);

        Thread.sleep(1100);  // We should have done the recreate by now

        SecureRandom secureRandom3 = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom3).isNotSameAs(secureRandom1);

        List<String> threadNames = Thread.getAllStackTraces().keySet()
                .stream()
                .map(Thread::getName)
                .collect(Collectors.toList());
        Assertions.assertThat(threadNames).contains("Task to recreate SecureRandom");

    }

    @Test
    @Order(5)
    void getSecureRandom_provider() {
        useProvider = true;
        SecureRandom secureRandom = JCASupportConfiguration.getInstance().getSecureRandom();
        Assertions.assertThat(secureRandom).isNotNull();

        Assertions.assertThat(secureRandom).isSameAs(TestSecureRandomProvider.secureRandomByProvider);

    }

    public static class TestSecureRandomProvider implements SecureRandomProvider {

        static SecureRandom secureRandomByProvider;

        @Override
        public SecureRandom get() {
            secureRandomByProvider = null;
            if (useProvider) {
                secureRandomByProvider = new SecureRandom();
                return secureRandomByProvider;
            }
            return null;
        }
    }
}