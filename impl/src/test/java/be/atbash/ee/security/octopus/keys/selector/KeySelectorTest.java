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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.filter.*;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.TestReflectionUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.security.Key;
import java.util.List;

/**
 *
 */

public class KeySelectorTest {

    private final KeySelector keySelector = new KeySelector();

    private static AtbashKey key1;
    private static AtbashKey key2;

    @BeforeAll
    public static void defineKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        key1 = keys.get(0); // It doesn't really matter, but we just need a value
        key2 = keys.get(1); // It doesn't really matter, but we just need a value

    }

    @BeforeEach
    public void setup() {
        // configure KeyManager
        TestConfig.registerDefaultConverters();
        TestConfig.addConfigValue("key.manager.class", FakeKeyManager.class.getName());
    }

    @AfterEach
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
        Assertions.assertThat(key).isNotNull();
    }

    @Test
    public void selectSecretKey_withNoKey() {

        SelectorCriteria criteria = SelectorCriteria.newBuilder().build();
        Key key = keySelector.selectSecretKey(criteria);
        Assertions.assertThat(key).isNull();
    }

    @Test
    public void selectAtbashKey_byKeyId() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(IdKeyFilter.class);

        String keyId = TestReflectionUtils.getValueOf(filter, "keyId");
        Assertions.assertThat(keyId).isEqualTo("kid");

    }

    @Test
    public void selectAtbashKey_bySecretKeyType() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withSecretKeyType(secretKeyType).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(SecretKeyTypeKeyFilter.class);

        SecretKeyType value = TestReflectionUtils.getValueOf(filter, "secretKeyType");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(value.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);

    }

    @Test
    public void selectAtbashKey_byKeyType() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withKeyType(KeyType.RSA).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_byAsymmetricPart() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(1);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(AsymmetricPartKeyFilter.class);

        AsymmetricPart value = TestReflectionUtils.getValueOf(filter, "asymmetricPart");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value).isEqualTo(AsymmetricPart.PRIVATE);

    }

    @Test
    public void selectAtbashKey_multipleFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").withKeyType(KeyType.RSA).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(2);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(IdKeyFilter.class);

        String keyId = TestReflectionUtils.getValueOf(filter, "keyId");
        Assertions.assertThat(keyId).isEqualTo("kid");

        filter = FakeKeyManager.keyFilters.get(1);
        Assertions.assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_FixedOrderFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        // Here the order is switched from ^^revious test, but the rest should be the same
        SelectorCriteria criteria = SelectorCriteria.newBuilder().withKeyType(KeyType.RSA).withId("kid").build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(2);
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(IdKeyFilter.class);

        String keyId = TestReflectionUtils.getValueOf(filter, "keyId");
        Assertions.assertThat(keyId).isEqualTo("kid");

        filter = FakeKeyManager.keyFilters.get(1);
        Assertions.assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value = TestReflectionUtils.getValueOf(filter, "keyType");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value).isEqualTo(KeyType.RSA);

    }

    @Test
    public void selectAtbashKey_AllFilters() throws NoSuchFieldException {

        FakeKeyManager.keys.add(key1);

        SecretKeyType secretKeyType = new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId("kid").withSecretKeyType(secretKeyType).withKeyType(KeyType.EC).withAsymmetricPart(AsymmetricPart.PUBLIC).build();
        AtbashKey key = keySelector.selectAtbashKey(criteria);
        Assertions.assertThat(key).isNotNull();

        Assertions.assertThat(key).isEqualTo(key1);
        Assertions.assertThat(FakeKeyManager.keyFilters).hasSize(4);
        // Id
        KeyFilter filter = FakeKeyManager.keyFilters.get(0);
        Assertions.assertThat(filter).isInstanceOf(IdKeyFilter.class);

        String keyId = TestReflectionUtils.getValueOf(filter, "keyId");
        Assertions.assertThat(keyId).isEqualTo("kid");

        // Secret Key Type
        filter = FakeKeyManager.keyFilters.get(1);
        Assertions.assertThat(filter).isInstanceOf(SecretKeyTypeKeyFilter.class);

        SecretKeyType value = TestReflectionUtils.getValueOf(filter, "secretKeyType");
        Assertions.assertThat(value).isNotNull();
        Assertions.assertThat(value.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(value.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);

        // Key type
        filter = FakeKeyManager.keyFilters.get(2);
        Assertions.assertThat(filter).isInstanceOf(KeyTypeKeyFilter.class);

        KeyType value2 = TestReflectionUtils.getValueOf(filter, "keyType");
        Assertions.assertThat(value2).isNotNull();
        Assertions.assertThat(value2).isEqualTo(KeyType.EC);

        // asymmetric
        filter = FakeKeyManager.keyFilters.get(3);
        Assertions.assertThat(filter).isInstanceOf(AsymmetricPartKeyFilter.class);

        AsymmetricPart value3 = TestReflectionUtils.getValueOf(filter, "asymmetricPart");
        Assertions.assertThat(value3).isNotNull();
        Assertions.assertThat(value3).isEqualTo(AsymmetricPart.PUBLIC);

    }

}