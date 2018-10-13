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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.MissingPasswordException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.config.PemKeyEncryption;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.resource.ResourceUtil;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.*;
import java.text.ParseException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */

public class KeyWriterTest {

    private static final char[] PASSWORD = "atbash".toCharArray();

    private KeyReader keyReader = new KeyReader();

    private JwtSupportConfiguration jwtSupportConfigurationMock;

    private KeyWriterFactory keyWriterFactory;

    private KeyWriter keyWriter;

    @Before
    public void setup() throws IllegalAccessException {
        jwtSupportConfigurationMock = Mockito.mock(JwtSupportConfiguration.class);

        keyWriterFactory = new KeyWriterFactory();
        keyWriterFactory.init();

        keyWriter = new KeyWriter();
        TestReflectionUtils.injectDependencies(keyWriter, keyWriterFactory, jwtSupportConfigurationMock);

    }

    @Test
    public void writeKeyResource_scenario1() throws IOException {
        when(jwtSupportConfigurationMock.getPemKeyEncryption()).thenReturn(PemKeyEncryption.PKCS1);
        when(jwtSupportConfigurationMock.getPKCS1EncryptionAlgorithm()).thenReturn("DES-EDE3-CBC");

        // scenario 1 RSA PKCS#1 format
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pk.pem", new TestPasswordLookup(PASSWORD));

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM, PASSWORD, null);

        String pemFile = new String(bytes);

        String expected = readFile("/rsa.pk.pem");
        // Since encryption is performed with some kind of Salt, the 2 values will never be the same.
        //However, first part needs to be identical.
        assertThat(pemFile.substring(0, 78)).isEqualTo(expected.substring(0, 78));

    }

    @Test
    public void writeKeyResource_scenario2() throws IOException {
        // scenario 2 RSA Pub format
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pk.pem", new TestPasswordLookup(PASSWORD));

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PUBLIC);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM, null, null);

        String pemFile = new String(bytes);

        String expected = readFile("/rsa.pub.pem");
        assertThat(pemFile).isEqualTo(expected);

    }

    @Test
    public void writeKeyResource_scenario3() {
        // scenario 3 RSA PKCS#8 format
        when(jwtSupportConfigurationMock.getPemKeyEncryption()).thenReturn(PemKeyEncryption.PKCS8);

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pk.pem", new TestPasswordLookup(PASSWORD));

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM, PASSWORD, null);

        String pemFile = new String(bytes);
        //System.out.println(pemFile);
        // TODO Not the same as rsa.pkcs8.pem, but these couldn't be read also.
        // TODO Investigate further
    }

    @Test
    public void writeKeyResource_scenario4() {
        // scenario 4 RSA not encrypted format
        when(jwtSupportConfigurationMock.getPemKeyEncryption()).thenReturn(PemKeyEncryption.NONE);

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pk.pem", new TestPasswordLookup(PASSWORD));

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM, PASSWORD, null);

        String pemFile = new String(bytes);
        //System.out.println(pemFile);
        // TODO Not the same as rsa.pk.free.pem
        // TODO Investigate further

    }

    @Test
    public void writeKeyResource_scenario5() throws IOException {
        // scenario 5 RSA private key as JWK
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", null);

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK, null, null);

        String jwk = new String(bytes);

        JSONObject data = JSONValue.parse(jwk, JSONObject.class);

        JSONObject expected = JSONValue.parse(readFile("/rsa.jwk"), JSONObject.class);

        for (String key : expected.keySet()) {
            assertThat(expected.getAsString(key)).isEqualTo(data.getAsString(key));
        }
    }

    @Test
    public void writeKeyResource_scenario7() throws IOException {
        // scenario 7 RSA private key as KeyStore
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", null);

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE, "atbash".toCharArray(), "atbash".toCharArray());

        FileOutputStream outputStream = new FileOutputStream("./scenario7.jks");
        outputStream.write(bytes);
        outputStream.close();

    }

    @Test(expected = MissingPasswordException.class)
    public void writeKeyResource_scenario7_missingKeyPassword() {
        // scenario 7 RSA private key as KeyStore
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", null);

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE, null, "atbash".toCharArray());

    }

    @Test(expected = MissingPasswordException.class)
    public void writeKeyResource_scenario7_missingFilePassword() {
        // scenario 7 RSA private key as KeyStore
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", null);

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE,  "atbash".toCharArray(), null);

    }

    @Test
    public void writeKeyResource_scenario9() throws IOException, ParseException {
        // scenario 9 RSA private key as JWKSet
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", null);

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWKSET, null, null);

        JWKSet jwkSet = JWKSet.parse(new String(bytes));

        JSONObject expected = JSONValue.parse(readFile("/rsa.jwk"), JSONObject.class);

        assertThat(jwkSet.getKeys()).hasSize(1);
        net.minidev.json.JSONObject data = jwkSet.getKeys().get(0).toJSONObject();

        for (String key : expected.keySet()) {
            assertThat(expected.getAsString(key)).isEqualTo(data.getAsString(key));
        }

    }

    private AtbashKey filterKeys(List<AtbashKey> keys, AsymmetricPart asymmetricPart) {
        AtbashKey result = null;
        for (AtbashKey key : keys) {
            if (key.getSecretKeyType().getAsymmetricPart() == asymmetricPart) {
                result = key;
            }
        }
        return result;
    }

    private String readFile(String fileName) throws IOException {

        String str;
        StringBuilder result = new StringBuilder();
        try (InputStream is = this.getClass().getResourceAsStream(fileName)) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            while ((str = reader.readLine()) != null) {
                result.append(str).append("\n");
            }
        }
        return result.toString();

    }
}