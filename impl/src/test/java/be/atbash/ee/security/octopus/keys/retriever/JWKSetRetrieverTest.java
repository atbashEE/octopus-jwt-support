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
package be.atbash.ee.security.octopus.keys.retriever;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.util.TestReflectionUtils;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


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

    @Before
    public void setUp() {
        Jadler.initJadler();
    }


    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void testRetrieveOK() throws Exception {

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        try {
            resourceRetriever.retrieveResource(new URL("http://localhost:" + port + "/c2id/jwks.json"));
            fail();
        } catch (IOException e) {
            assertThat(e.getMessage()).startsWith("Connection refused");
        }
    }

    @Test
    public void testConnectTimeoutWithProxy() throws Exception {

        ServerSocket serverSocket = new ServerSocket(0);
        int proxyPort = serverSocket.getLocalPort();
        serverSocket.close();

        JWKSetRetriever resourceRetriever = new JWKSetRetriever(50, 0);
        resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", proxyPort)));

        try {
            resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));
            fail();
        } catch (IOException e) {
            assertThat(e.getMessage()).startsWith("Connection refused");
        }
    }

    @Test
    public void testReadTimeout() {

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        try {
            resourceRetriever.retrieveResource(new URL("http://localhost:" + Jadler.port() + "/c2id/jwks.json"));
            fail();
        } catch (IOException e) {
            assertThat(e.getMessage()).isEqualTo("Read timed out");
        }
    }

    @Test
    public void testSizeLimit() throws Exception {

        RSAKey rsaKey = new RSAKey.Builder(generateRSAKeys()).keyID("kid").build();
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

        try {
            resourceRetriever.retrieveResource(url);
            fail();
        } catch (IOException e) {
            // Size overrun exception poses as file not found
            // FIXME Can we bring this message back?
            assertThat(e.getMessage()).startsWith("Parsing of content of 'http://localhost:");
        }
    }

    private RSAPublicKey generateRSAKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("something")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> atbashKeys = generator.generateKeys(generationParameters);
        RSAPublicKey result = null;
        for (AtbashKey atbashKey : atbashKeys) {
            if (atbashKey.getKey() instanceof RSAPublicKey) {
                result = (RSAPublicKey) atbashKey.getKey();
            }
        }
        return result;
    }
}