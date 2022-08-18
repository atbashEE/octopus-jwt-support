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
package be.atbash.ee.security.octopus.jwt;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.exception.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.*;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * This in one of the high level test for testing complete process end to end.
 * Focusing on no wrapping in JWT, or using signed JWT
 */
public class JWSTest {
    private static final String KID_SIGN = "sign";

    private TestLogger logger;
    private Payload payload;

    @BeforeEach
    public void setup() {
        payload = new Payload();
        payload.setValue("JUnit");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

        logger = TestLoggerFactory.getTestLogger(KeySelector.class);
    }

    @AfterEach
    public void teardown() {
        TestLoggerFactory.clear();
        TestConfig.resetConfig();
    }

    @Test
    public void encodingNone() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        Payload data = new JWTDecoder().decode(encoded, Payload.class).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_HMAC() {

        AtbashKey key = TestKeys.generateOCTKeys("hmacID").get(0);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(key);
        KeyManager keyManager = new ListKeyManager(keys);
        TestKeySelector keySelector = new TestKeySelector(keyManager);  // Using TestKeySelector with ListKeyManager is more realistic for Key selection
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_HMAC_WrongKey() {

        SecureRandom random = new SecureRandom();

        byte[] secret1 = new byte[32];
        random.nextBytes(secret1);
        byte[] secret2 = new byte[32];
        random.nextBytes(secret2);

        AtbashKey key1 = HmacSecretUtil.generateSecretKey("hmacID", secret1);
        AtbashKey key2 = HmacSecretUtil.generateSecretKey("hmacID", secret2);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key1)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new SingleKeySelector(key2);
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(encoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);
    }

    @Test
    public void encodingJWT__hmac_TamperedPayload() {

        AtbashKey key = TestKeys.generateOCTKeys("hmacID").get(0);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        KeySelector keySelector = new SingleKeySelector(key);
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);
    }

    private String tamperWithPayload(String encoded) {
        String[] jwtParts = encoded.split("\\.");
        String content = new String(Base64.getDecoder().decode(jwtParts[1]));
        String updatedContent = content.replaceAll("JUnit", "Spock");
        jwtParts[1] = Base64.getEncoder().encodeToString(updatedContent.getBytes(StandardCharsets.UTF_8));

        return jwtParts[0] + '.' + jwtParts[1] + '.' + jwtParts[2];
    }

    @Test
    public void encodingJWT_RSA() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        // Check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"RS256\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_RSA_otherAlgo() {
        TestConfig.addConfigValue("jwt.sign.rsa.algo", "PS512");

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        // Check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"PS512\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_RSA_WrongKeyForVerification() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);


        List<AtbashKey> keysOther = TestKeys.generateRSAKeys(KID_SIGN);
        keyManager = new ListKeyManager(keysOther);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(encoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);
    }

    @Test
    public void encodingJWT_RSA_tamperedPayload() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);

    }

    @Test
    public void encodingJWT_RSA_WrongKeyType() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        Assertions.assertThatThrownBy(() -> new JWTEncoder().encode(payload, parameters))
                .isInstanceOf(KeyTypeException.class);

    }

    @Test
    public void encodingJWT_EC() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        // check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"ES256\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_EC_customAlgo() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "P-521");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        // check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"ES512\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_EC_WrongKeyForVerification() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        List<AtbashKey> keysOther = TestKeys.generateECKeys(KID_SIGN, "P-256");
        keyManager = new ListKeyManager(keysOther);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(encoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);
    }

    @Test
    public void encodingJWT_EC_tamperedPayload() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);

    }

    @Test
    public void encodingJWT_EC_WrongKeyType() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        Assertions.assertThatThrownBy(() -> new JWTEncoder().encode(payload, parameters))
                .isInstanceOf(KeyTypeException.class);

    }

    @Test
    public void encodingJWT_EC_unsupportedCurve() {

        List<AtbashKey> keys = TestKeys.generateECKeys(KID_SIGN, "prime192v1");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        Assertions.assertThatThrownBy(() -> new JWTEncoder().encode(payload, parameters))
                .isInstanceOf(UnsupportedECCurveException.class);
    }

    @Test
    public void encodingJWT_noKeyMatch() {

        List<AtbashKey> keys = TestKeys.generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        keys.clear();  // remove all keys
        KeySelector keySelector = new TestKeySelector(keyManager);
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(encoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);

        Assertions.assertThat(logger.getLoggingEvents()).hasSize(1);
        Assertions.assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
        Assertions.assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("(OCT-KEY-010) No or multiple keys found for criteria :\n" +
                " KeySelectorCriteria{\n" +
                "     KeyFilter{keyId='sign'}\n" +
                "     KeyFilter{part='PUBLIC'}\n" +
                "}");
    }

    @Test
    public void encodingJWT_OKP() {
        List<AtbashKey> keys = TestKeys.generateOKPKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        // Check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"EdDSA\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector).getData();

        Assertions.assertThat(payload).usingRecursiveComparison().isEqualTo(data);
    }

    @Test
    public void encodingJWT_OKP_tamperedPayload() {
        List<AtbashKey> keys = TestKeys.generateOKPKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);
        String updatedEncoded = tamperWithPayload(encoded);

        // Check algo in header
        String header = new String(Base64.getDecoder().decode(encoded.split("\\.")[0]));
        Assertions.assertThat(header).contains("\"alg\":\"EdDSA\"");

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector))
                .isInstanceOf(InvalidJWTException.class);
    }

    @Test
    public void encodingJWT_OKP_wrongKey() {
        List<AtbashKey> keys = TestKeys.generateOKPKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        Assertions.assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);
        String updatedEncoded = tamperWithPayload(encoded);

        List<AtbashKey> keysOther = TestKeys.generateOKPKeys(KID_SIGN);
        keyManager = new ListKeyManager(keysOther);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Assertions.assertThatThrownBy(() -> new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector, null))
                .isInstanceOf(InvalidJWTException.class);
    }
}
