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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.MyColor;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.TestKeySelector;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTDecoderTest {

    private JWTDecoder decoder = new JWTDecoder();

    @Test
    public void decode() {

        String data = "{\"pets\":\"dog,cat\",\"dateValue\":\"2017-11-15\",\"valueForClass\":\"Atbash\"}";

        Map<String, String> result = decoder.decode(data, HashMap.class);


        assertThat(result.keySet()).containsOnlyOnce("pets", "dateValue", "valueForClass");
    }

    @Test
    public void decode_customSerializer() {
        List<AtbashKey> keys = generateRSAKeys("kid");
        JWTParameters parameters = getJwtParameters(keys);
        JWTEncoder encoder = new JWTEncoder();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("value", "200,150,100").build();

        ListKeyManager keyManager = new ListKeyManager(keys);

        String json = encoder.encode(claims, parameters);

        JWTData<MyColor> myColor = decoder.decode(json, MyColor.class, new TestKeySelector(keyManager), null);
        assertThat(myColor).isNotNull();
        MyColor data = myColor.getData();
        assertThat(data).isNotNull();
        assertThat(data.getR()).isEqualTo(200);
        assertThat(data.getG()).isEqualTo(150);
        assertThat(data.getB()).isEqualTo(100);

    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private JWTParameters getJwtParameters(List<AtbashKey> keys) {

        ListKeyManager keyManager = new ListKeyManager(keys);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).as("We should have 1 Private key").hasSize(1);

        return JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keyList.get(0))
                .build();
    }

}