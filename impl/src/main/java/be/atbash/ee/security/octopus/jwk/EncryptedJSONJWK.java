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
package be.atbash.ee.security.octopus.jwk;

import be.atbash.ee.security.octopus.exception.MissingPasswordException;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.JWK;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import be.atbash.util.StringUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 *
 */

public final class EncryptedJSONJWK {

    private static final List<String> GENERAL_NAMES = Arrays.asList("kty", "use", "key_ops", "alg", "kid", "crv");

    private EncryptedJSONJWK() {
    }

    public static String encryptedOutput(JWK jwk, char[] password) {
        if (StringUtils.isEmpty(password)) {
            throw new MissingPasswordException(MissingPasswordException.ObjectType.ENCRYPTION, null);
        }
        JsonObject fullJWK = jwk.toJSONObject().build();

        JsonObjectBuilder encryptedJWK = Json.createObjectBuilder();
        JsonObjectBuilder sensitiveProperties = Json.createObjectBuilder();

        for (Map.Entry<String, JsonValue> entry : fullJWK.entrySet()) {
            if (GENERAL_NAMES.contains(entry.getKey())) {
                encryptedJWK.add(entry.getKey(), entry.getValue());
            } else {
                sensitiveProperties.add(entry.getKey(), entry.getValue());
            }
        }

        String json = sensitiveProperties.build().toString();
        encryptedJWK.add("enc", EncryptionHelper.encode(json, password));

        return encryptedJWK.build().toString();
    }
}
