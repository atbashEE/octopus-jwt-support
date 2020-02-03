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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.config.PemKeyEncryption;
import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.resource.ResourceUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
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

    @BeforeEach
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

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM, PASSWORD);

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

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.PEM);

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
        when(jwtSupportConfigurationMock.isJWKEncrypted()).thenReturn(false);

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK);

        String jwk = new String(bytes);

        Jsonb jsonb = JsonbBuilder.create();

        JsonObject data = jsonb.fromJson(jwk, JsonObject.class);

        JsonObject expected = jsonb.fromJson(readFile("/rsa.jwk"), JsonObject.class);

        for (String key : expected.keySet()) {
            assertThat(expected.getString(key)).isEqualTo(data.getString(key));
        }
    }

    @Test
    public void writeKeyResource_RSA_encrypted() throws IOException {
        // RSA Private key is 'encrypted'
        when(jwtSupportConfigurationMock.isJWKEncrypted()).thenReturn(true);

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");
        // FIXME use this technique everywhere to filter keys instead of KeySelector.
        KeyFilter filter = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE);
        AtbashKey privateKey = filter.filter(keys).get(0);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK, "atbash".toCharArray());
        Jsonb jsonb = JsonbBuilder.create();

        JsonObject data = jsonb.fromJson(new String(bytes), JsonObject.class);
        assertThat(data.keySet()).containsOnly("kty", "kid", "enc");

        // test to get the AtbashKey back, see KeyReaderJWKTest
    }

    @Test
    public void writeKeyResource_scenario7() throws IOException {
        // scenario 7 RSA private key as KeyStore
        when(jwtSupportConfigurationMock.getKeyStoreType()).thenReturn("jks");

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE, "atbash".toCharArray(), "atbash".toCharArray());

        FileOutputStream outputStream = new FileOutputStream("./scenario7.jks");
        outputStream.write(bytes);
        outputStream.close();

    }

    @Test
    public void writeKeyResource_scenario7_missingKeyPassword() {
        // scenario 7 RSA private key as KeyStore
        when(jwtSupportConfigurationMock.getKeyStoreType()).thenReturn("jks");

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        Assertions.assertThrows(MissingPasswordException.class, () -> keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE, "atbash".toCharArray()));

    }

    @Test
    public void writeKeyResource_scenario7_missingFilePassword() {
        // scenario 7 RSA private key as KeyStore
        when(jwtSupportConfigurationMock.getKeyStoreType()).thenReturn("jks");

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        Assertions.assertThrows(MissingPasswordException.class, () -> keyWriter.writeKeyResource(privateKey, KeyResourceType.KEYSTORE, "atbash".toCharArray(), null));

    }

    @Test
    public void writeKeyResource_scenario9() throws IOException, ParseException {
        // scenario 9 RSA private key as JWKSet
        when(jwtSupportConfigurationMock.isJWKEncrypted()).thenReturn(false);

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");

        AtbashKey privateKey = filterKeys(keys, AsymmetricPart.PRIVATE);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWKSET);

        JWKSet jwkSet = JWKSet.parse(new String(bytes));
        assertThat(jwkSet.getKeys()).hasSize(1);

        Jsonb jsonb = JsonbBuilder.create();
        JsonObject dataAsSet = jsonb.fromJson(new String(bytes), JsonObject.class);
        JsonObject data = dataAsSet.getJsonArray("keys").getJsonObject(0);

        JsonObject expected = jsonb.fromJson(readFile("/rsa.jwk"), JsonObject.class);

        for (String key : expected.keySet()) {
            assertThat(expected.getString(key)).isEqualTo(data.getString(key));
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