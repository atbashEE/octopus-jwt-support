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
package be.atbash.ee.security.octopus.keys.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.config.PemKeyEncryption;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.LocalKeyManager;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.reader.DefaultKeyResourceTypeProvider;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceTypeProvider;
import be.atbash.ee.security.octopus.keys.reader.password.ConfigKeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class JwtSupportConfigurationTest {

    private JwtSupportConfiguration configuration;

    private TestLogger logger = TestLoggerFactory.getTestLogger(JwtSupportConfiguration.class);

    @BeforeEach
    public void setup() {
        configuration = new JwtSupportConfiguration();
        TestConfig.registerDefaultConverters();
    }

    @AfterEach
    public void cleanup() {
        TestConfig.resetConfig();
        logger.clear();
    }

    @Test
    public void getKeysLocation() {
        TestConfig.addConfigValue("keys.location", "configLocation");

        String keysLocation = configuration.getKeysLocation();
        assertThat(keysLocation).isEqualTo("configLocation");
    }

    @Test
    public void getKeysLocation_isOptional() {
        // TODO But within code later on it is always required.
        String keysLocation = configuration.getKeysLocation();
        assertThat(keysLocation).isNull();
    }

    @Test
    public void getPasswordLookup() {
        KeyResourcePasswordLookup lookup = configuration.getPasswordLookup();

        assertThat(lookup).isInstanceOf(ConfigKeyResourcePasswordLookup.class);
    }

    @Test
    public void getPasswordLookup_config() {
        TestConfig.addConfigValue("lookup.password.class", TestPasswordLookup.class.getName());
        KeyResourcePasswordLookup lookup = configuration.getPasswordLookup();

        assertThat(lookup).isInstanceOf(TestPasswordLookup.class);
    }

    @Test
    public void getPasswordLookup_required() {
        TestConfig.addConfigValue("lookup.password.class", " ");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getPasswordLookup());

    }

    @Test
    public void getPasswordLookup_WrongType() {
        TestConfig.addConfigValue("lookup.password.class", String.class.getName());
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getPasswordLookup());
    }

    @Test
    public void getKeyManager() {
        KeyManager keyManager = configuration.getKeyManager();

        assertThat(keyManager).isInstanceOf(LocalKeyManager.class);
    }

    @Test
    public void getKeyManager_config() {
        TestConfig.addConfigValue("key.manager.class", TestKeyManager.class.getName());
        KeyManager keyManager = configuration.getKeyManager();

        assertThat(keyManager).isInstanceOf(TestKeyManager.class);
    }

    @Test
    public void getKeyManager_required() {
        TestConfig.addConfigValue("key.manager.class", " ");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getKeyManager());

    }

    @Test
    public void getKeyManager_WrongType() {
        TestConfig.addConfigValue("key.manager.class", String.class.getName());
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getKeyManager());
    }

    //

    @Test
    public void getKeyResourceTypeProvider() {
        KeyResourceTypeProvider provider = configuration.getKeyResourceTypeProvider();

        assertThat(provider).isInstanceOf(DefaultKeyResourceTypeProvider.class);
    }

    @Test
    public void getKeyResourceTypeProvider_config() {
        TestConfig.addConfigValue("key.resourcetype.provider.class", TestKeyResourceTypeProvider.class.getName());
        KeyResourceTypeProvider provider = configuration.getKeyResourceTypeProvider();

        assertThat(provider).isInstanceOf(TestKeyResourceTypeProvider.class);
    }

    @Test
    public void getKeyResourceTypeProvider_required() {
        TestConfig.addConfigValue("key.resourcetype.provider.class", " ");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getKeyResourceTypeProvider());

    }

    @Test
    public void getKeyResourceTypeProvider_WrongType() {
        TestConfig.addConfigValue("key.resourcetype.provider.class", String.class.getName());
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getKeyResourceTypeProvider());
    }

    //
    @Test
    public void getPemKeyEncryption() {
        // Default
        PemKeyEncryption encryption = configuration.getPemKeyEncryption();
        assertThat(encryption).isEqualTo(PemKeyEncryption.PKCS8);
    }

    @Test
    public void getPemKeyEncryption_pkcs1() {
        TestConfig.addConfigValue("key.pem.encryption", "PKCS1");
        TestConfig.registerDefaultConverters();
        PemKeyEncryption encryption = configuration.getPemKeyEncryption();
        assertThat(encryption).isEqualTo(PemKeyEncryption.PKCS1);
    }

    @Test
    public void getPemKeyEncryption_Wrong() {
        TestConfig.addConfigValue("key.pem.encryption", "value");
        TestConfig.registerDefaultConverters();

        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getPemKeyEncryption());

    }

    @Test
    public void getPemKeyEncryption_Empty() {
        TestConfig.addConfigValue("key.pem.encryption", "");
        TestConfig.registerDefaultConverters();

        assertThat(configuration.getPemKeyEncryption()).isEqualTo(PemKeyEncryption.NONE);

    }

    @Test
    public void getClockSkewSeconds() {
        assertThat(configuration.getClockSkewSeconds()).isEqualTo(60);
    }

    @Test
    public void getClockSkewSeconds_zeroAllowed() {
        TestConfig.addConfigValue("jwt.clock.skew.secs", "0");
        assertThat(configuration.getClockSkewSeconds()).isEqualTo(0);
    }

    @Test
    public void getClockSkewSeconds_invalid() {
        TestConfig.addConfigValue("jwt.clock.skew.secs", "-1");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getClockSkewSeconds());
    }

    @Test
    public void getClockSkewSeconds_wrongType() {
        TestConfig.addConfigValue("jwt.clock.skew.secs", "12.34");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getClockSkewSeconds());
    }

    @Test
    public void getDefaultJWEAlgorithmEC() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.EC", "ECDH-ES");
        JWEAlgorithm algorithm = configuration.getDefaultJWEAlgorithmEC();
        assertThat(algorithm).isEqualTo(JWEAlgorithm.ECDH_ES);
    }

    @Test
    public void getDefaultJWEAlgorithmEC_default() {
        // Default
        JWEAlgorithm algorithm = configuration.getDefaultJWEAlgorithmEC();
        assertThat(algorithm).isEqualTo(JWEAlgorithm.ECDH_ES_A256KW);
    }

    @Test
    public void getDefaultJWEAlgorithmEC_invalid() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.EC", "RSA-OAEP-256");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getDefaultJWEAlgorithmEC());

    }

    @Test
    public void getDefaultJWEAlgorithmEC_empty() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.EC", "");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getDefaultJWEAlgorithmEC());
    }

    @Test
    public void getDefaultJWEAlgorithmOCT() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.OCT", "A192KW");
        JWEAlgorithm algorithm = configuration.getDefaultJWEAlgorithmOCT();
        assertThat(algorithm).isEqualTo(JWEAlgorithm.A192KW);
    }

    @Test
    public void getDefaultJWEAlgorithmOCT_default() {
        // Default
        JWEAlgorithm algorithm = configuration.getDefaultJWEAlgorithmOCT();
        assertThat(algorithm).isEqualTo(JWEAlgorithm.A256KW);
    }

    @Test
    public void getDefaultJWEAlgorithmOCT_invalid() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.OCT", "RSA-OAEP-256");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getDefaultJWEAlgorithmOCT());

    }

    @Test
    public void getDefaultJWEAlgorithmOCT_empty() {
        TestConfig.addConfigValue("jwt.jwe.algorithm.default.OCT", "");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getDefaultJWEAlgorithmOCT());
    }

    @Test
    public void getJWKSetCachePeriod_default() {
        String cachePeriod = configuration.getJWKSetCachePeriod();
        assertThat(cachePeriod).isEqualTo("24h");
    }

    @Test
    public void getJWKSetCachePeriod() {
        TestConfig.addConfigValue("jwt.remote.jwk.cache.period", "15m");
        String cachePeriod = configuration.getJWKSetCachePeriod();
        assertThat(cachePeriod).isEqualTo("15m");
    }

    @Test
    public void getJWKSetCachePeriod_invalid() {
        TestConfig.addConfigValue("jwt.remote.jwk.cache.period", "abc");
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getJWKSetCachePeriod());
    }

    @Test
    public void getReaderOrder() {
        // The Default Order
        List<KeyResourceType> order = configuration.getReaderOrder();
        assertThat(order).containsExactly(KeyResourceType.JWKSET, KeyResourceType.JWK, KeyResourceType.PEM, KeyResourceType.KEYSTORE);
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void getReaderOrder_custom() {
        // some order
        TestConfig.addConfigValue("jwt.reader.order", "PEM, JWK, JWKSET, KEYSTORE");
        List<KeyResourceType> order = configuration.getReaderOrder();
        assertThat(order).containsExactly(KeyResourceType.PEM, KeyResourceType.JWK, KeyResourceType.JWKSET, KeyResourceType.KEYSTORE);
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void getReaderOrder_wrong_values() {
        // some order
        TestConfig.addConfigValue("jwt.reader.order", "just, some, values");
        List<KeyResourceType> order = configuration.getReaderOrder();

        assertThat(order).containsExactly(KeyResourceType.JWKSET, KeyResourceType.JWK, KeyResourceType.PEM, KeyResourceType.KEYSTORE);
        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(4);
        assertThat(events.get(0).getMessage()).isEqualTo("Parameter 'jwt.reader.order' must contain only values of 'KeyResourceType' but found 'just'.");
        assertThat(events.get(3).getMessage()).isEqualTo("Parameter 'jwt.reader.order' resulted in an empty list. Taken the default order.");
    }

    @Test
    public void getReaderOrder_caseInsensitive() {
        // some order
        TestConfig.addConfigValue("jwt.reader.order", "JwkSet");
        List<KeyResourceType> order = configuration.getReaderOrder();
        assertThat(order).containsExactly(KeyResourceType.JWKSET);
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void getReaderOrder_noCheckOnDoubles() {
        // some order
        TestConfig.addConfigValue("jwt.reader.order", "JwkSet, JWKSET");
        List<KeyResourceType> order = configuration.getReaderOrder();
        assertThat(order).containsExactly(KeyResourceType.JWKSET, KeyResourceType.JWKSET);
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void getSaltLengthPasswordBasedEJWEEncryption() {
        int length = configuration.getSaltLengthPasswordBasedEJWEEncryption();
        assertThat(length).isEqualTo(8);
    }

    @Test
    public void getSaltLengthPasswordBasedEJWEEncryption_value() {
        TestConfig.addConfigValue("jwt.jwe.pwbased.salt.length", "16");
        int length = configuration.getSaltLengthPasswordBasedEJWEEncryption();
        assertThat(length).isEqualTo(16);
    }

    @Test
    public void getSaltLengthPasswordBasedEJWEEncryption_invalid1() {
        TestConfig.addConfigValue("jwt.jwe.pwbased.salt.length", "7");
        ConfigurationException exception = Assertions.assertThrows(ConfigurationException.class, () -> configuration.getSaltLengthPasswordBasedEJWEEncryption());
        assertThat(exception.getMessage()).isEqualTo("The value for the parameter 'jwt.jwe.pwbased.salt.length' must be at minimum 8 but was '7'.");
    }

    @Test
    public void getSaltLengthPasswordBasedEJWEEncryption_invalid2() {
        TestConfig.addConfigValue("jwt.jwe.pwbased.salt.length", "-1");
        ConfigurationException exception = Assertions.assertThrows(ConfigurationException.class, () -> configuration.getSaltLengthPasswordBasedEJWEEncryption());
        assertThat(exception.getMessage()).isEqualTo("The value for the parameter 'jwt.jwe.pwbased.salt.length' must be at minimum 8 but was '-1'.");
    }

    @Test
    public void getSaltLengthPasswordBasedEJWEEncryption_invalid3() {
        TestConfig.addConfigValue("jwt.jwe.pwbased.salt.length", "NotNumber");
        Assertions.assertThrows(NumberFormatException.class, () -> configuration.getSaltLengthPasswordBasedEJWEEncryption());
    }

    public static class TestKeyManager implements KeyManager {

        @Override
        public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
            return null;
        }
    }

    public static class TestKeyResourceTypeProvider implements KeyResourceTypeProvider {

        @Override
        public KeyResourceType determineKeyResourceType(String path) {
            return null;
        }
    }
}