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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.filter.*;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.security.Key;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeySelectorTest {

    private KeySelector keySelector = new KeySelector();

    private TestLogger logger;

    private static AtbashKey key1;
    private static AtbashKey key2;

    @BeforeClass
    public static void defineKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        key1 = keys.get(0); // It doesn't really matter, but we just need a value
        key2 = keys.get(1); // It doesn't really matter, but we just need a value

    }

    @Before
    public void setup() {
        // configure KeyManager
        TestConfig.registerDefaultConverters();
        TestConfig.addConfigValue("key.manager.class", FakeKeyManager.class.getName());

        logger = TestLoggerFactory.getTestLogger(KeySelector.class);
    }

    @After
    public void teardown() {
        TestConfig.resetConfig();
        FakeKeyManager.reset();
        TestLoggerFactory.clear();
    }

    @Test
    public void selectSecretKey_withKey() {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").build();
        Key key = keySelector.selectSecretKey(criteria);
        assertThat(key).isNotNull();
    }

    @Test
    public void selectSecretKey_withNoKey() {

        SelectorCriteria criteria = SelectorCriteria.newBuilder().build();
        Key key = keySelector.selectSecretKey(criteria);
        assertThat(key).isNull();
    }

    @Test
    public void selectAtbashKey_byKeyId() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(IdKeyFilter.class);

        assertThat(TestReflectionUtils.getValueOf(filter, "keyId")).isEqualTo("kid");

    }

    @Test
    public void selectAtbashKey_bySecretKeyType() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withSecretKeyType(secretKeyType).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(SecretKeyTypeKeyFilter.class);

        SecretKeyType value = TestReflectionUtils.getValueOf(filter, "secretKeyType");
        assertThat(value).isNotNull();
        assertThat(value.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(value.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);

    }

    @Test
    public void selectAtbashKey_byKeyType() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withKeyType(KeyType.RSA).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_byAsymmetricPart() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(AsymmetricPartKeyFilter.class);

        AsymmetricPart value = TestReflectionUtils.getValueOf(filter, "asymmetricPart");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo(AsymmetricPart.PRIVATE);

    }

    @Test
    public void selectAtbashKey_multipleFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").withKeyType(KeyType.RSA).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(2);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(IdKeyFilter.class);

        assertThat(TestReflectionUtils.getValueOf(filter, "keyId")).isEqualTo("kid");

        filter = FakeKeyManager.keyFilters.get(1);
        assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_FixedOrderFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        // Here the order is switched from ^^revious test, but the rest should be the same
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withKeyType(KeyType.RSA).withId("kid").build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(2);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(IdKeyFilter.class);

        assertThat(TestReflectionUtils.getValueOf(filter, "keyId")).isEqualTo("kid");

        filter = FakeKeyManager.keyFilters.get(1);
        assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_AllFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").withSecretKeyType(secretKeyType).withKeyType(KeyType.EC).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNotNull();

        assertThat(key).isEqualTo(key1);
        assertThat(FakeKeyManager.keyFilters).hasSize(4);
        // Id
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        assertThat(filter).isInstanceOf(IdKeyFilter.class);

        assertThat(TestReflectionUtils.getValueOf(filter, "keyId")).isEqualTo("kid");

        // Secret Key Type
        filter = FakeKeyManager.keyFilters.get(1);
        assertThat(filter).isInstanceOf(SecretKeyTypeKeyFilter.class);

        SecretKeyType value = TestReflectionUtils.getValueOf(filter, "secretKeyType");
        assertThat(value).isNotNull();
        assertThat(value.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(value.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);

        // Key type
        filter = FakeKeyManager.keyFilters.get(2);
        assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value2 = TestReflectionUtils.getValueOf(filter, "keyType");
        assertThat(value2).isNotNull();
        assertThat(value2).isEqualTo(KeyType.EC);

        // asymmetric
        filter = FakeKeyManager.keyFilters.get(3);
        assertThat(filter).isInstanceOf(AsymmetricPartKeyFilter.class);

        AsymmetricPart value3 = TestReflectionUtils.getValueOf(filter, "asymmetricPart");
        assertThat(value3).isNotNull();
        assertThat(value3).isEqualTo(AsymmetricPart.PUBLIC);

    }

    @Test
    public void selectAtbashKey_NoMatch() {

        SelectorCriteria criteria = SelectorCriteria.newBuilder().build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNull();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("(OCT-KEY-010)");

    }

    @Test
    public void selectAtbashKey_multipleMatch() {
        FakeKeyManager.keys.add(key1);
        FakeKeyManager.keys.add(key2);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        assertThat(key).isNull();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("(OCT-KEY-011)");

    }

}