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
package be.atbash.ee.security.octopus.jwt;

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.OCTGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.*;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JWETest {

    public static final String KID_SIGN = "sign";
    public static final String KID_ENCRYPT = "encrypt";
    private Payload payload;

    @Before
    public void setup() {
        payload = new Payload();
        payload.setValue("JUnit");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

    }

    @Test
    public void encodingJWE_RSA() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);
        keys.addAll(generateRSAKeys(KID_ENCRYPT));

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        criteria = SelectorCriteria.newBuilder().withId(KID_ENCRYPT).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> encryptKeyList = keyManager.retrieveKeys(criteria);

        assertThat(encryptKeyList).as("We should have 1 Public key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    @Test
    public void encodingJWE_EC() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "P-256");
        keys.addAll(generateECKeys(KID_ENCRYPT, "P-256"));

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        criteria = SelectorCriteria.newBuilder().withId(KID_ENCRYPT).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> encryptKeyList = keyManager.retrieveKeys(criteria);

        assertThat(encryptKeyList).as("We should have 1 Public key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    // FIXME Test with correct BC Curve name but not supported by Nimbus

    @Test
    public void encodingJWE_OCT() {

        List<AtbashKey> signKeyList = generateOCTKeys(KID_SIGN);

        assertThat(signKeyList).as("We should have 1 key for signing").hasSize(1);

        List<AtbashKey> encryptKeyList = generateOCTKeys(KID_ENCRYPT);

        assertThat(encryptKeyList).as("We should have 1 key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        List<AtbashKey> keys = new ArrayList<>();
        keys.addAll(signKeyList);
        keys.addAll(encryptKeyList);

        ListKeyManager keyManager = new ListKeyManager(keys);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private List<AtbashKey> generateECKeys(String kid, String curveName) {
        ECGenerationParameters generationParameters = new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId(kid)
                .withCurveName(curveName)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private List<AtbashKey> generateOCTKeys(String kid) {
        OCTGenerationParameters generationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

}
