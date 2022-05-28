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
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.writer.KeyWriter;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KeyReaderJWKTest {

    public static final String PASSWORD = "atbash";

    private KeyReaderJWK keyReader = new KeyReaderJWK();

    private KeyWriter keyWriter = new KeyWriter();

    @Test
    void parse_RSA_enc() throws ParseException {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        AtbashKey privateKey = Filters.findPrivateKey(keys);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK, PASSWORD.toCharArray());
        String json = new String(bytes);

        assertThat(json).contains("\"enc\":");
        assertThat(json).contains("\"kty\":\"RSA\"");
        List<AtbashKey> parsedKeys = keyReader.parse(json, "somePath", new TestPasswordLookup(null, PASSWORD.toCharArray()));
        AtbashKey parsedKey = Filters.findPrivateKey(parsedKeys);

        // Both keys are the same when their encoded format is the same.
        assertThat(parsedKey.getKey().getEncoded()).isEqualTo(privateKey.getKey().getEncoded());

    }

    @Test
    void parse_EC_enc() throws ParseException {
        List<AtbashKey> keys = TestKeys.generateECKeys("kid", Curve.P_256.getName());
        AtbashKey privateKey = Filters.findPrivateKey(keys);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK, PASSWORD.toCharArray());
        String json = new String(bytes);

        assertThat(json).contains("\"enc\":");
        assertThat(json).contains("\"kty\":\"EC\"");
        List<AtbashKey> parsedKeys = keyReader.parse(json, "somePath", new TestPasswordLookup(null, PASSWORD.toCharArray()));
        AtbashKey parsedKey = Filters.findPrivateKey(parsedKeys);

        //TODO Both keys are the same but encrypted is not the same hmmmm
        assertThat(parsedKey.getKey()).isEqualTo(privateKey.getKey());

    }

    @Test
    void parse_OKP_enc() throws ParseException {
        List<AtbashKey> keys = TestKeys.generateOKPKeys("kid");
        AtbashKey privateKey = Filters.findPrivateKey(keys);

        byte[] bytes = keyWriter.writeKeyResource(privateKey, KeyResourceType.JWK, PASSWORD.toCharArray());
        String json = new String(bytes);

        assertThat(json).contains("\"enc\":");
        assertThat(json).contains("\"kty\":\"OKP\"");
        List<AtbashKey> parsedKeys = keyReader.parse(json, "somePath", new TestPasswordLookup(null, PASSWORD.toCharArray()));
        AtbashKey parsedKey = Filters.findPrivateKey(parsedKeys);

        // Both keys are the same when their encoded format is the same.
        assertThat(parsedKey.getKey().getEncoded()).isEqualTo(privateKey.getKey().getEncoded());

    }

    @Test
    void parse_b64() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");
        AtbashKey publicKey = Filters.findPublicKey(keys);

        byte[] bytes = keyWriter.writeKeyResource(publicKey, KeyResourceType.JWK);
        String content = Base64.getEncoder().encodeToString(bytes);

        List<AtbashKey> parsedKeys = keyReader.parseContent(content, null);

        assertThat(parsedKeys).hasSize(1);
        // Both keys are the same when their encoded format is the same.
        assertThat(parsedKeys.get(0).getKey().getEncoded()).isEqualTo(publicKey.getKey().getEncoded());

    }
}