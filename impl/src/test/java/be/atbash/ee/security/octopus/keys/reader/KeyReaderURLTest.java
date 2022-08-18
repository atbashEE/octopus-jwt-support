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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.util.resource.ResourceUtil;
import net.jadler.Jadler;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Scanner;

class KeyReaderURLTest {

    private final KeyReader reader = new KeyReader();

    @BeforeEach
    public void setUp() {

        Jadler.initJadler();
    }

    @AfterEach
    public void teardown() {
        Jadler.closeJadler();
    }

    @Test
    void readKeyResource_pem() throws IOException {
        ResourceUtil resourceUtil = ResourceUtil.getInstance();
        InputStream inputStream = resourceUtil.getStream("classpath:rsa.pk.free.pem");

        String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/data")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(fileContent);

        List<AtbashKey> keys = reader.readKeyResource(URI.create("http://localhost:" + Jadler.port() + "/data"), null);
        Assertions.assertThat(keys).hasSize(2);
    }

    @Test
    void readKeyResource_jwk() throws IOException {
        ResourceUtil resourceUtil = ResourceUtil.getInstance();
        InputStream inputStream = resourceUtil.getStream("classpath:rsa.jwk");

        String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/data")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(fileContent);

        List<AtbashKey> keys = reader.readKeyResource(URI.create("http://localhost:" + Jadler.port() + "/data"), null);
        Assertions.assertThat(keys).hasSize(2);
    }

    @Test
    void readKeyResource_jwks() throws IOException {
        ResourceUtil resourceUtil = ResourceUtil.getInstance();
        InputStream inputStream = resourceUtil.getStream("classpath:test.jwkset");

        String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/data")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(fileContent);

        List<AtbashKey> keys = reader.readKeyResource(URI.create("http://localhost:" + Jadler.port() + "/data"), null);
        Assertions.assertThat(keys).hasSize(4);
    }
}