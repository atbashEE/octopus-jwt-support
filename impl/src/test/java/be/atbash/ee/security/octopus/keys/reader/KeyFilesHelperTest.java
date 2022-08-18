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
package be.atbash.ee.security.octopus.keys.reader;

import com.google.common.collect.ImmutableList;
import net.jadler.Jadler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.List;

import org.assertj.core.api.Assertions;

class KeyFilesHelperTest {

    private final KeyFilesHelper helper = new KeyFilesHelper();

    private final TestLogger logger = TestLoggerFactory.getTestLogger(KeyFilesHelper.class);

    @AfterEach
    public void tearDown() {
        logger.clear();
        Jadler.closeJadler();
    }

    @Test
    void determineKeyFiles() {
        List<String> files = helper.determineKeyFiles("classpath:test.jwkset");
        Assertions.assertThat(files).containsOnly("classpath:test.jwkset");
    }

    @Test
    void determineKeyFiles_wrongExtension() {
        List<String> files = helper.determineKeyFiles("classpath:test.wrong");
        Assertions.assertThat(files).isEmpty();
        ImmutableList<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        Assertions.assertThat(loggingEvents).hasSize(1);
        Assertions.assertThat(loggingEvents.get(0).getLevel()).isEqualTo(Level.WARN);
        Assertions.assertThat(loggingEvents.get(0).getMessage()).isEqualTo("(OCT-KEY-012) Unable to determine type of 'classpath:test.wrong'");
    }

    @Test
    void determineKeyFiles_file() {
        List<String> files = helper.determineKeyFiles("file:./src/test/resources/rsa.pub.pem");
        Assertions.assertThat(files).containsOnly("file:./src/test/resources/rsa.pub.pem");
    }

    @Test
    void determineKeyFiles_directory() {
        List<String> files = helper.determineKeyFiles("file:./target/test-classes");
        Assertions.assertThat(files.size()).isGreaterThan(10); // There are many files and when one is added, it should no fail the test
        ImmutableList<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        Assertions.assertThat(loggingEvents.size()).isGreaterThan(5);

    }

    @Test
    void determineKeyFiles_ClasspathDirectory() {
        List<String> files = helper.determineKeyFiles("classpath:");
        Assertions.assertThat(files.size()).isGreaterThan(10); // There are many files and when one is added, it should no fail the test
        ImmutableList<LoggingEvent> loggingEvents = logger.getLoggingEvents();
        Assertions.assertThat(loggingEvents.size()).isGreaterThan(5);

    }

    @Test
    void determineKeyFiles_URL() {
        Jadler.initJadler();
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/auth/realms/public")
                .respond()
                .withStatus(200);

        List<String> files = helper.determineKeyFiles("http://localhost:" + Jadler.port() + "/auth/realms/public");
        Assertions.assertThat(files).containsOnly("http://localhost:" + Jadler.port() + "/auth/realms/public");
    }
}