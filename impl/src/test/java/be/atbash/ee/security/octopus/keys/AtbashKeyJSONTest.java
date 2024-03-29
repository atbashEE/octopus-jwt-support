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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.SingleKeySelector;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class AtbashKeyJSONTest {

    private static final String KID = "kidValue";

    @Test
    public void testJSONSupport_RSAPrivate() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateRSAKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_RSAPublic() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateRSAKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_ECPrivate() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateECKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        //Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo("EC"); // Original is ECDSA

        // Alternative test by alternativeTest_ECSerialization()
        //Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_ECPublic() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateECKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        //Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());
        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo("EC"); // Original is ECDSA


        // Alternative test by alternativeTest_ECSerialization()
        //Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJsonSupport_OCT() {
        List<AtbashKey> keys = TestKeys.generateOCTKeys(KID);
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keys.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();
        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo("AES");
        Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keys.get(0).getKey().getEncoded());
    }

    @Test
    public void testJSONSupport_OKPPrivate() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateOKPKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());

        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void testJSONSupport_OKPPublic() {
        ListKeyManager keyManager = new ListKeyManager(TestKeys.generateOKPKeys(KID));

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        AtbashKey key = new JWTDecoder().decode(json, AtbashKey.class).getData();

        Assertions.assertThat(key.getKey().getAlgorithm()).isEqualTo(keyList.get(0).getKey().getAlgorithm());

        // When encoded representation (PKCS#8) is the same, I guess both keys are the same
        Assertions.assertThat(key.getKey().getEncoded()).isEqualTo(keyList.get(0).getKey().getEncoded());

    }

    @Test
    public void alternativeTest_ECSerialization() {
        // Alternative for testJSONSupport_ECPrivate()
        // If we can sign and verify some data, I guess we are safe

        // Get the keys
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        ListKeyManager keyManager = new ListKeyManager(atbashKeys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);

        AtbashKey privateOriginalKey = keyList.get(0);

        criteria = SelectorCriteria.newBuilder().withId(KID).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        keyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(keyList).hasSize(1);
        AtbashKey publicOriginalKey = keyList.get(0);

        // 1. Test with the original keys (to verify if JWTEncoder and JWTDecoder doesn't have a problem)
        testWithKeys(privateOriginalKey, publicOriginalKey);

        // Manipulated Private key (to JSON and back)
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(privateOriginalKey, parameters);

        AtbashKey privateManipulatedKey = new JWTDecoder().decode(json, AtbashKey.class).getData();

        // 2. Test with the manipulated private against public
        testWithKeys(privateManipulatedKey, publicOriginalKey);

        // Manipulated Private key (to JSON and back)
        parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        json = new JWTEncoder().encode(publicOriginalKey, parameters);

        AtbashKey publicManipulatedKey = new JWTDecoder().decode(json, AtbashKey.class).getData();

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
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
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