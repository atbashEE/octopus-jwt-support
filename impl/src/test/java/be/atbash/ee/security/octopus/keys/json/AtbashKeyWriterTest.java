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
package be.atbash.ee.security.octopus.keys.json;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.ListKeyManager;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.util.base64.Base64Codec;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class AtbashKeyWriterTest {

    private static final String KID = "kidValue";

    @Test
    public void testWriteJSONString() {
        ListKeyManager keyManager = new ListKeyManager(generateRSAKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).

                hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        JSONObject data = (JSONObject) JSONValue.parse(json);

        assertThat(data.getAsString("kid")).isEqualTo(KID);

        String key = new String(Base64Codec.decode(data.getAsString("key")));

        data = (JSONObject) JSONValue.parse(key);

        assertThat(data.keySet()).containsOnly("p", "kty", "q", "d", "e", "kid", "qi", "dp", "dq", "n");


    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

}