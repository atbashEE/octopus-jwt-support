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
package be.atbash.ee.security.octopus.keys.retriever;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.util.TestReflectionUtils;
import net.jadler.Jadler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.*;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;


public class JWKSetRetrieverTest {

    @Test
    public void testDefaultSettings() throws NoSuchFieldException {

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();

        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "connectTimeout")).isEqualTo(0);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "readTimeout")).isEqualTo(0);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "sizeLimit")).isEqualTo(0);
        assertThat(resourceRetriever.getProxy()).isNull();
    }


    @Test
    public void testSetters() throws NoSuchFieldException {

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(100, 200, 300);

        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "connectTimeout")).isEqualTo(100);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "readTimeout")).isEqualTo(200);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "sizeLimit")).isEqualTo(300);

        resourceRetriever.setProxy(Proxy.NO_PROXY);
        assertThat(resourceRetriever.getProxy()).isEqualTo(Proxy.NO_PROXY);
    }


    @Test
    public void testTimeoutConstructor() throws NoSuchFieldException {

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(100, 200);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "connectTimeout")).isEqualTo(100);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "readTimeout")).isEqualTo(200);
        assertThat((Integer) TestReflectionUtils.getValueOf(resourceRetriever, "sizeLimit")).isEqualTo(0);
    }

    @BeforeEach
    public void setUp() {
        Jadler.initJadler();
    }


    @AfterEach
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void testRetrieveOK() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();
        JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));

        JWK data = jwkSet.getKeyByKeyId("kid");
        assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
    }


    @Test
    public void testRetrieveOK_loop() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(0, 0, 0);

        for (int i = 0; i < 100; i++) {
            JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));

            JWK data = jwkSet.getKeyByKeyId("kid");
            assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
        }
    }

    @Test
    public void testRetrieveOKWithoutContentType() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();
        JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));

        JWK data = jwkSet.getKeyByKeyId("kid");
        assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
    }

    @Test
    public void testIgnoreInvalidContentType() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        String invalidContentType = "moo/boo/foo";

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withContentType(invalidContentType)
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();

        JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));
        JWK data = jwkSet.getKeyByKeyId("kid");
        assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
    }

    @Test
    public void testRetrieve2xxWithProxy() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();
        resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", Jadler.port())));
        JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));

        JWK data = jwkSet.getKeyByKeyId("kid");
        assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
    }

    @Test
    public void testRetrieve2xx() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever();
        JWKSet jwkSet = resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));

        JWK data = jwkSet.getKeyByKeyId("kid");
        assertThat(data.toJSONObject().build().toString()).isEqualTo(rsaKey.toJSONObject().build().toString());
    }

    @Test
    public void testConnectTimeout() throws Exception {

        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();
        serverSocket.close();

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(50, 0);

        URL url = new URL("http://localhost:" + port + "/c2id/jwks.json");
        IOException e = Assertions.assertThrows(IOException.class, () -> resourceRetriever.retrieveResource(url));
        assertThat(e.getMessage()).startsWith("Connection refused");

    }

    @Test
    public void testConnectTimeoutWithProxy() throws Exception {

        ServerSocket serverSocket = new ServerSocket(0);
        int proxyPort = serverSocket.getLocalPort();
        serverSocket.close();

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(50, 0);
        resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", proxyPort)));

        URL url = new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json");
        IOException e = Assertions.assertThrows(IOException.class, () -> resourceRetriever.retrieveResource(url));
        assertThat(e.getMessage()).startsWith("Connection refused");

    }

    @Test
    public void testReadTimeout() throws MalformedURLException {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withDelay(100L, TimeUnit.MILLISECONDS)
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(set.toJSONObject().toString());

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(0, 50);

        URL url = new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json");
        IOException e = Assertions.assertThrows(IOException.class, () -> resourceRetriever.retrieveResource(url));
        assertThat(e.getMessage()).isEqualTo("Read timed out");

    }

    @Test
    public void testSizeLimit() throws Exception {
        AtbashKey publicKey = Filters.findPublicKey(TestKeys.generateRSAKeys("kid"));
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid").build();
        JWKSet set = new JWKSet(rsaKey);

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/c2id/jwks.json")
                .respond()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(set.toJSONObject().toString());

        int sizeLimit = 50;
        JWKSetRetriever resourceRetriever = new JWKSetRetriever(0, 0, sizeLimit);

        URL url = new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json");

        IOException e = Assertions.assertThrows(IOException.class, () -> resourceRetriever.retrieveResource(url));
        // Size overrun exception poses as file not found
        // FIXME Can we bring this message back?
        assertThat(e.getMessage()).startsWith("Parsing of content of 'http://localhost:");

    }
}