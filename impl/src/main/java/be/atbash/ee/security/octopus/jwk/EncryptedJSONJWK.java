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
package be.atbash.ee.security.octopus.jwk;

import be.atbash.ee.security.octopus.MissingPasswordException;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;

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
        JSONObject fullJWK = jwk.toJSONObject();

        JSONObject encryptedJWK = new JSONObject();
        JSONObject sensitiveProperties = new JSONObject();

        for (Map.Entry<String, Object> entry : fullJWK.entrySet()) {
            if (GENERAL_NAMES.contains(entry.getKey())) {
                encryptedJWK.appendField(entry.getKey(), entry.getValue());
            } else {
                sensitiveProperties.appendField(entry.getKey(), entry.getValue());
            }
        }

        String json = sensitiveProperties.toJSONString();
        encryptedJWK.appendField("enc", EncryptionHelper.encode(json, password));

        return encryptedJWK.toJSONString();
    }
}
