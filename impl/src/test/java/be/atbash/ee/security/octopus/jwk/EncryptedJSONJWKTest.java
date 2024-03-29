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
package be.atbash.ee.security.octopus.jwk;

import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import java.security.SecureRandom;
import java.util.Base64;

import org.assertj.core.api.Assertions;

/**
 *
 */

public class EncryptedJSONJWKTest {

    private static final char[] PASSWORD = "atbash".toCharArray();

    @Test
    public void encryptedOutput() {
        byte[] key = new byte[20];
        new SecureRandom().nextBytes(key);
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(key)
                .algorithm(new Algorithm("algo"))
                .keyID("keyId")
                .build();

        String json = EncryptedJSONJWK.encryptedOutput(jwk, PASSWORD);
        // Check all the fields
        Assertions.assertThat(json).contains("\"alg\":\"algo\"");
        Assertions.assertThat(json).contains("\"kty\":\"oct\"");
        Assertions.assertThat(json).contains("\"kid\":\"keyId\"");
        Assertions.assertThat(json).contains("\"enc\":\"");

        Jsonb jsonb = JsonbBuilder.create();
        JsonObject jsonObject = jsonb.fromJson(json, JsonObject.class);

        // Get the value of field enc, and decrypt it with the password
        String encJson = EncryptionHelper.decode(jsonObject.getString(JWKIdentifiers.ENCRYPTION_ALGORITHM), PASSWORD);

        // decrypted value is a json again
        JsonObject secureJson = jsonb.fromJson(encJson, JsonObject.class);
        Assertions.assertThat(secureJson.keySet()).containsOnly("k");
        // check if value is same as the byteArray we started with
        Assertions.assertThat(secureJson.getString("k")).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(key));

    }

    @Test
    public void encryptedOutput_passwordRequired() {
        byte[] key = new byte[20];
        new SecureRandom().nextBytes(key);
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(key)
                .algorithm(new Algorithm("algo"))
                .keyID("keyId")
                .build();

        Assertions.assertThatThrownBy(() -> EncryptedJSONJWK.encryptedOutput(jwk, null))
                .isInstanceOf(MissingPasswordException.class)
                .hasMessage("Password required for encryption/decryption");

    }
    @Test
    public void encryptedOutput_passwordRequired2() {
        byte[] key = new byte[20];
        new SecureRandom().nextBytes(key);
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(key)
                .algorithm(new Algorithm("algo"))
                .keyID("keyId")
                .build();

        Assertions.assertThatThrownBy(() -> EncryptedJSONJWK.encryptedOutput(jwk, "  ".toCharArray()))
                .isInstanceOf(MissingPasswordException.class)
                .hasMessage("Password required for encryption/decryption");

    }
}