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
package be.atbash.ee.security.octopus.keys.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class JwtSupportConfigurationTest {

    private JwtSupportConfiguration configuration;

    @Before
    public void setup() {
        configuration = new JwtSupportConfiguration();
        TestConfig.registerDefaultConverters();
    }

    @After
    public void cleanup() {
        TestConfig.resetConfig();
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

    @Test(expected = ConfigurationException.class)
    public void getPasswordLookup_required() {
        TestConfig.addConfigValue("lookup.password.class", " ");
        configuration.getPasswordLookup();

    }

    @Test(expected = ConfigurationException.class)
    public void getPasswordLookup_WrongType() {
        TestConfig.addConfigValue("lookup.password.class", String.class.getName());
        configuration.getPasswordLookup();
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

    @Test(expected = ConfigurationException.class)
    public void getKeyManager_required() {
        TestConfig.addConfigValue("key.manager.class", " ");
        configuration.getKeyManager();

    }

    @Test(expected = ConfigurationException.class)
    public void getKeyManager_WrongType() {
        TestConfig.addConfigValue("key.manager.class", String.class.getName());
        configuration.getKeyManager();
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

    @Test(expected = ConfigurationException.class)
    public void getKeyResourceTypeProvider_required() {
        TestConfig.addConfigValue("key.resourcetype.provider.class", " ");
        configuration.getKeyResourceTypeProvider();

    }

    @Test(expected = ConfigurationException.class)
    public void getKeyResourceTypeProvider_WrongType() {
        TestConfig.addConfigValue("key.resourcetype.provider.class", String.class.getName());
        configuration.getKeyResourceTypeProvider();
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

    @Test(expected = ConfigurationException.class)
    public void getPemKeyEncryption_Wrong() {
        TestConfig.addConfigValue("key.pem.encryption", "value");
        TestConfig.registerDefaultConverters();

        configuration.getPemKeyEncryption();

    }

    @Test
    public void getPemKeyEncryption_Empty() {
        TestConfig.addConfigValue("key.pem.encryption", "");
        TestConfig.registerDefaultConverters();

        assertThat(configuration.getPemKeyEncryption()).isEqualTo(PemKeyEncryption.NONE);

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