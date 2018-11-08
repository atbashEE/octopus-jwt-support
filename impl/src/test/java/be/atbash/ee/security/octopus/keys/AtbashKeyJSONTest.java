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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.*;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class AtbashKeyJSONTest {

    private static final String KID = "kidValue";

    @Test
    public void testJSONSupport_RSAPrivate() {
        ListKeyManager keyManager = new ListKeyManager(generateRSAKeys());

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class);

        assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_RSAPublic() {
        ListKeyManager keyManager = new ListKeyManager(generateRSAKeys());

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class);

        assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_ECPrivate() {
        ListKeyManager keyManager = new ListKeyManager(generateECKeys());

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class);

        //assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        assertThat(key.getKey().getAlgorithm()).isEqualTo("EC"); // Original is ECDSA

        // Alternative test by alternativeTest_ECSerialization()
        //assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_ECPublic() {
        ListKeyManager keyManager = new ListKeyManager(generateECKeys());

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class);

        //assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        assertThat(key.getKey().getAlgorithm()).isEqualTo("EC"); // Original is ECDSA


        assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    private List<AtbashKey> generateRSAKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(KID)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private List<AtbashKey> generateECKeys() {
        ECGenerationParameters parameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId(KID)
                .withCurveName("secp256r1")
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(parameters);
    }

    @Test
    public void alternativeTest_ECSerialization() {
        // Alternative for testJSONSupport_ECPrivate()
        // If we can sign and verify some data, I guess we are safe

        // Get the keys
        List<AtbashKey> atbashKeys = generateECKeys();
        ListKeyManager keyManager = new ListKeyManager(atbashKeys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);

        AtbashKey privateOriginalKey = keyList.get(0);

        criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        keyList = keyManager.retrieveKeys(criteria);

        assertThat(keyList).hasSize(1);
        AtbashKey publicOriginalKey = keyList.get(0);

        // 1. Test with the original keys (to verify if JWTEncoder and JWTDecoder doesn't have a problem)
        testWithKeys(privateOriginalKey, publicOriginalKey);

        // Manipulated Private key (to JSON and back)
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(privateOriginalKey, parameters);

        AtbashKey privateManipulatedKey = new JWTDecoder().decode(json, AtbashKey.class);

        // 2. Test with the manipulated private against public
        testWithKeys(privateManipulatedKey, publicOriginalKey);

        // Manipulated Private key (to JSON and back)
        parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        json = new JWTEncoder().encode(publicOriginalKey, parameters);

        AtbashKey publicManipulatedKey = new JWTDecoder().decode(json, AtbashKey.class);

        // 2. Test with the manipulated public against private
        testWithKeys(privateOriginalKey, publicManipulatedKey);

        // 3. Test with both manipulated keys
        testWithKeys(privateManipulatedKey, publicManipulatedKey);

    }

    private void testWithKeys(AtbashKey privateOriginalKey, AtbashKey publicOriginalKey) {
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(privateOriginalKey)
                .build();

        JWTEncoder encoder = new JWTEncoder();
        Payload payload = getPayload();
        String encoded = encoder.encode(payload, parameters);

        KeySelector keySelector = new SingleKeySelector(publicOriginalKey);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    private Payload getPayload() {
        Payload result = new Payload();
        result.setValue("JUnit");
        result.setNumber(42);
        result.getMyList().add("permission1");
        result.getMyList().add("permission2");

        return result;
    }


}