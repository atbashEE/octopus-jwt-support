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

import be.atbash.ee.security.octopus.UnsupportedKeyType;
import be.atbash.ee.security.octopus.exception.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.*;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import be.atbash.util.base64.Base64Codec;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This in one of the high level test for testing complete process end to end.
 * Focusing on no wrapping in JWT, or using signed JWT
 */
public class JWTTest {

    private static final String KID_SIGN = "sign";

    private TestLogger logger;
    private Payload payload;

    @Before
    public void setup() {
        payload = new Payload();
        payload.setValue("JUnit");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

        logger = TestLoggerFactory.getTestLogger(KeySelector.class);
    }

    @After
    public void teardown() {
        TestLoggerFactory.clear();
    }

    @Test
    public void encodingNone() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        Payload data = new JWTDecoder().decode(encoded, Payload.class);

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    @Test
    public void encodingJWT_HMAC() {

        AtbashKey key = generateOCTKey();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        KeySelector keySelector = new SingleKeySelector(key);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    @Test(expected = InvalidJWTException.class)
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
        new JWTDecoder().decode(encoded, Payload.class, keySelector, null);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT__hmac_TamperedPayload() {

        AtbashKey key = generateOCTKey();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();
        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        KeySelector keySelector = new SingleKeySelector(key);
        new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector, null);
    }

    private String tamperWithPayload(String encoded) {
        String[] jwtParts = encoded.split("\\.");
        String content = new String(Base64Codec.decode(jwtParts[1]));
        String updatedContent = content.replaceAll("JUnit", "Spock");
        jwtParts[1] = Base64Codec.encodeToString(updatedContent.getBytes(StandardCharsets.UTF_8), false);

        return jwtParts[0] + '.' + jwtParts[1] + '.' + jwtParts[2];
    }

    @Test
    public void encodingJWT_RSA() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_RSA_WrongKeyForVerification() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);


        List<AtbashKey> keysOther = generateRSAKeys(KID_SIGN);
        keyManager = new ListKeyManager(keysOther);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        new JWTDecoder().decode(encoded, Payload.class, keySelector, null);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_RSA_tamperedPayload() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector, null);

    }

    @Test(expected = UnsupportedKeyType.class)
    public void encodingJWT_RSA_WrongKeyType() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        new JWTEncoder().encode(payload, parameters);

    }

    @Test
    public void encodingJWT_EC() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();

        assertThat(payload).isEqualToComparingFieldByField(data);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_EC_WrongKeyForVerification() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);


        List<AtbashKey> keysOther = generateECKeys(KID_SIGN, "P-256");
        keyManager = new ListKeyManager(keysOther);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        new JWTDecoder().decode(encoded, Payload.class, keySelector, null);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_EC_tamperedPayload() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        String updatedEncoded = tamperWithPayload(encoded);

        criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);

        KeySelector keySelector = new SingleKeySelector(publicList.get(0));
        new JWTDecoder().decode(updatedEncoded, Payload.class, keySelector, null);

    }

    @Test(expected = UnsupportedKeyType.class)
    public void encodingJWT_EC_WrongKeyType() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "P-256");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        new JWTEncoder().encode(payload, parameters);

    }

    @Test(expected = UnsupportedECCurveException.class)
    public void encodingJWT_EC_unsupportedCurve() {

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "prime192v1");

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        new JWTEncoder().encode(payload, parameters);
    }

    @Test(expected = InvalidJWTException.class)
    public void encodingJWT_noKeyMatch() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(signKeyList.get(0))
                .build();

        String encoded = new JWTEncoder().encode(payload, parameters);

        keys.clear();  // remove all keys
        KeySelector keySelector = new TestKeySelector(keyManager);
        try {
            new JWTDecoder().decode(encoded, Payload.class, keySelector, null);
        } finally {

            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("(OCT-KEY-010) No or multiple keys found for criteria :\n" +
                    " KeySelectorCriteria{\n" +
                    "     KeyFilter{keyId='sign'}\n" +
                    "     KeyFilter{part='PUBLIC'}\n" +
                    "}");
        }
    }

    private AtbashKey generateOCTKey() {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        return HmacSecretUtil.generateSecretKey("hmacID", secret);
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
}
