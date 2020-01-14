/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.exception.UnsupportedECCurveException;
import be.atbash.ee.security.octopus.exception.UnsupportedKeyLengthException;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.OCTGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.TestKeySelector;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JWETest {

    private static final String KID_SIGN = "sign";
    private static final String KID_ENCRYPT = "encrypt";

    private TestLogger logger;
    private Payload payload;

    @Mock
    private JwtSupportConfiguration jwtSupportConfigurationMock;

    private JWTEncoder jwtEncoder = new JWTEncoder();

    @BeforeEach
    public void setup() throws NoSuchFieldException {
        payload = new Payload();
        payload.setValue("JUnit");
        payload.setNumber(42);
        payload.getMyList().add("permission1");
        payload.getMyList().add("permission2");

        logger = TestLoggerFactory.getTestLogger(KeySelector.class);

        TestReflectionUtils.setFieldValue(jwtEncoder, "jwtSupportConfiguration", jwtSupportConfigurationMock);
    }

    @AfterEach
    public void teardown() {
        TestLoggerFactory.clear();
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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    @Test
    public void encodingJWE_EC() throws ParseException {
        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmEC()).thenReturn(JWEAlgorithm.ECDH_ES_A256KW);

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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

        JWEObject jweObject = JWEObject.parse(encoded);
        assertThat(jweObject.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES_A256KW);

    }

    @Test
    public void encodingJWE_EC_unsupportedCurve() {

        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmEC()).thenReturn(JWEAlgorithm.ECDH_ES_A256KW);

        List<AtbashKey> keys = generateECKeys(KID_SIGN, "prime192v1");
        keys.addAll(generateECKeys(KID_ENCRYPT, "prime192v1"));

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
        Assertions.assertThrows(UnsupportedECCurveException.class, () -> jwtEncoder.encode(payload, parameters));
    }

    @Test
    public void encodingJWE_RSA_EC() {

        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmEC()).thenReturn(JWEAlgorithm.ECDH_ES_A256KW);

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);
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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    @Test
    public void encodingJWE_EC_RSA() {
        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmEC()).thenReturn(JWEAlgorithm.ECDH_ES_A256KW);

        List<AtbashKey> keys = generateECKeys(KID_ENCRYPT, "P-256");
        keys.addAll(generateRSAKeys(KID_SIGN));

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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    @Test
    public void encodingJWE_RSA_WrongKeyType() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);
        keys.addAll(generateRSAKeys(KID_ENCRYPT));

        ListKeyManager keyManager = new ListKeyManager(keys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(KID_SIGN).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> signKeyList = keyManager.retrieveKeys(criteria);

        assertThat(signKeyList).as("We should have 1 Private key for signing").hasSize(1);

        criteria = SelectorCriteria.newBuilder().withId(KID_ENCRYPT).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> encryptKeyList = keyManager.retrieveKeys(criteria);

        assertThat(encryptKeyList).as("We should have 1 Public key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        Assertions.assertThrows(UnsupportedKeyType.class, () -> jwtEncoder.encode(payload, parameters));
    }

    @Test
    public void encodingJWE_OCT() {
        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmOCT()).thenReturn(JWEAlgorithm.A256KW);

        List<AtbashKey> signKeyList = generateOCTKeys(KID_SIGN, 256);

        assertThat(signKeyList).as("We should have 1 key for signing").hasSize(1);

        List<AtbashKey> encryptKeyList = generateOCTKeys(KID_ENCRYPT, 256);

        assertThat(encryptKeyList).as("We should have 1 key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        String encoded = jwtEncoder.encode(payload, parameters);

        List<AtbashKey> keys = new ArrayList<>();
        keys.addAll(signKeyList);
        keys.addAll(encryptKeyList);

        ListKeyManager keyManager = new ListKeyManager(keys);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

    }

    @Test
    public void encodingJWE_NoKeyMatch() {

        List<AtbashKey> signKeys = generateRSAKeys(KID_SIGN);
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

        String encoded = jwtEncoder.encode(payload, parameters);

        keyManager = new ListKeyManager(signKeys);  // Missing keys from encryption
        KeySelector keySelector = new TestKeySelector(keyManager);
        Assertions.assertThrows(InvalidJWTException.class, () -> new JWTDecoder().decode(encoded, Payload.class, keySelector, null));
        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.ERROR);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("(OCT-KEY-010) No or multiple keys found for criteria :\n" +
                " KeySelectorCriteria{\n" +
                "     KeyFilter{keyId='encrypt'}\n" +
                "     KeyFilter{part='PRIVATE'}\n" +
                "}");


    }

    @Test
    public void encodingJWE_OCT_wrongKeyLength() {
        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmOCT()).thenReturn(JWEAlgorithm.A256KW);

        List<AtbashKey> signKeyList = generateOCTKeys(KID_SIGN, 256);

        assertThat(signKeyList).as("We should have 1 key for signing").hasSize(1);

        List<AtbashKey> encryptKeyList = generateOCTKeys(KID_ENCRYPT, 224);

        assertThat(encryptKeyList).as("We should have 1 key for encryption").hasSize(1);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(signKeyList.get(0))
                .withSecretKeyForEncryption(encryptKeyList.get(0))
                .build();

        Assertions.assertThrows(UnsupportedKeyLengthException.class, () -> jwtEncoder.encode(payload, parameters));
    }

    @Test
    public void encodingJWE_RSA_wrongKey() {

        List<AtbashKey> keys = generateRSAKeys(KID_SIGN);
        List<AtbashKey> signKeys = new ArrayList<>(keys);
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

        String encoded = jwtEncoder.encode(payload, parameters);

        // Generate another key for encryption
        signKeys.addAll(generateRSAKeys(KID_ENCRYPT));
        keyManager = new ListKeyManager(signKeys);

        KeySelector keySelector = new TestKeySelector(keyManager);

        Exception e = Assertions.assertThrows(AtbashUnexpectedException.class, () -> new JWTDecoder().decode(encoded, Payload.class, keySelector, null));
        assertThat(e).isInstanceOf(AtbashUnexpectedException.class);
        assertThat(e.getCause()).isInstanceOf(JOSEException.class);
        // Message can vary

    }

    @Test
    public void encodingJWE_RSA_tamperedPayload() {

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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);

        Exception e = Assertions.assertThrows(AtbashUnexpectedException.class, () -> new JWTDecoder().decode(new StringBuilder(encoded).deleteCharAt(450).insert(450, "1").toString(), Payload.class, keySelector, null));

        assertThat(e).isInstanceOf(AtbashUnexpectedException.class);
        assertThat(e.getCause()).isInstanceOf(JOSEException.class);
        assertThat(e.getCause().getCause().getMessage()).isEqualTo("AES/GCM/NoPadding decryption failed: Tag mismatch!");

    }

    @Test
    public void encodingJWE_RSA_tamperedIV() {

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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);

        Exception e = Assertions.assertThrows(AtbashUnexpectedException.class, () -> new JWTDecoder().decode(new StringBuilder(encoded).deleteCharAt(440).insert(440, "1").toString(), Payload.class, keySelector, null));

        assertThat(e).isInstanceOf(AtbashUnexpectedException.class);
        assertThat(e.getCause()).isInstanceOf(JOSEException.class);
        assertThat(e.getCause().getCause().getMessage()).isEqualTo("AES/GCM/NoPadding decryption failed: Tag mismatch!");

    }

    @Test
    public void encodingJWE_EC_customAlgo() throws ParseException {
        when(jwtSupportConfigurationMock.getDefaultJWEAlgorithmEC()).thenReturn(JWEAlgorithm.ECDH_ES);

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

        String encoded = jwtEncoder.encode(payload, parameters);

        KeySelector keySelector = new TestKeySelector(keyManager);
        Payload data = new JWTDecoder().decode(encoded, Payload.class, keySelector, null).getData();
        assertThat(data).isEqualToComparingFieldByField(payload);

        JWEObject jweObject = JWEObject.parse(encoded);
        assertThat(jweObject.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
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

    private List<AtbashKey> generateOCTKeys(String kid, int keySize) {
        OCTGenerationParameters generationParameters = new OCTGenerationParameters.OCTGenerationParametersBuilder()
                .withKeyId(kid)
                .withKeySize(keySize)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

}
