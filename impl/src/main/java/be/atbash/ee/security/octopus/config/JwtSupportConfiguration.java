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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.LocalKeyManager;
import be.atbash.ee.security.octopus.keys.reader.DefaultKeyResourceTypeProvider;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceTypeProvider;
import be.atbash.ee.security.octopus.keys.reader.password.ConfigKeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;
import be.atbash.util.reflection.ClassUtils;
import com.nimbusds.jose.JWSAlgorithm;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus JWT Support Configuration")
public class JwtSupportConfiguration extends AbstractConfiguration implements ModuleConfig {

    private static final List<JWSAlgorithm> RSA_SUPPORTED_ALGOS = Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384
            , JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);

    /**
     * The return value can also be a directory where multiple files are located (and retrieved).
     *
     * @return Location, file or directory where the keys are located.
     */
    @ConfigEntry
    public String getKeysLocation() {
        // TODO Optional, but afterwards we throw exception when empty
        // Can't we force the checks here? (so question : when octopus-jwt-support module added, isn't the parameter always required or not?)
        // be.atbash.ee.security.octopus.keys.LocalKeyManager.checkKeyLoading
        return getOptionalValue("keys.location", String.class);
    }

    @ConfigEntry
    public KeyResourcePasswordLookup getPasswordLookup() {

        String passwordClass = getOptionalValue("lookup.password.class", ConfigKeyResourcePasswordLookup.class.getName(), String.class);
        if (StringUtils.isEmpty(passwordClass)) {
            throw new ConfigurationException("Configuration parameter lookup.password.class is required to have a value.");
        }

        if (!ClassUtils.isAvailable(passwordClass)) {
            throw new ConfigurationException("Configuration parameter lookup.password.class class not found.");
        }

        Class<?> passwordClz = ClassUtils.forName(passwordClass);
        if (!KeyResourcePasswordLookup.class.isAssignableFrom(passwordClz)) {
            throw new ConfigurationException("Configuration parameter lookup.password.class must be an implementation of be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup");
        }
        return ClassUtils.newInstance(passwordClz);
    }

    @ConfigEntry
    public KeyManager getKeyManager() {

        String keyManagerClass = getOptionalValue("key.manager.class", LocalKeyManager.class.getName(), String.class);

        if (StringUtils.isEmpty(keyManagerClass)) {
            throw new ConfigurationException("Configuration parameter key.manager.class is required to have a value.");
        }

        if (!ClassUtils.isAvailable(keyManagerClass)) {
            throw new ConfigurationException("Configuration parameter key.manager.class class not found.");
        }

        Class<?> keyManagerClz = ClassUtils.forName(keyManagerClass);
        if (!KeyManager.class.isAssignableFrom(keyManagerClz)) {
            throw new ConfigurationException("Configuration parameter key.manager.class must be an implementation of be.atbash.ee.security.octopus.keys.KeyManager");
        }

        return ClassUtils.newInstance(keyManagerClz);
    }

    @ConfigEntry
    public KeyResourceTypeProvider getKeyResourceTypeProvider() {
        String keyResourceTypeProviderClass = getOptionalValue("key.resourcetype.provider.class", DefaultKeyResourceTypeProvider.class.getName(), String.class);

        if (StringUtils.isEmpty(keyResourceTypeProviderClass)) {
            throw new ConfigurationException("Configuration parameter key.resourcetype.provider.class is required to have a value.");
        }

        if (!ClassUtils.isAvailable(keyResourceTypeProviderClass)) {
            throw new ConfigurationException("Configuration parameter key.resourcetype.provider.class class not found.");
        }

        Class<?> keyResourceTypeProviderClz = ClassUtils.forName(keyResourceTypeProviderClass);
        if (!KeyResourceTypeProvider.class.isAssignableFrom(keyResourceTypeProviderClz)) {
            throw new ConfigurationException("Configuration parameter key.resourcetype.provider.class must be an implementation of be.atbash.ee.security.octopus.keys.reader.KeyResourceTypeProvider");
        }

        return ClassUtils.newInstance(keyResourceTypeProviderClz);

    }

    @ConfigEntry
    public PemKeyEncryption getPemKeyEncryption() {
        try {
            return getOptionalValue("key.pem.encryption", PemKeyEncryption.PKCS8, PemKeyEncryption.class);
        } catch (IllegalArgumentException e) {
            // When empty value, we need to return NONE
            String stringValue = getOptionalValue("key.pem.encryption", "", String.class);
            if (StringUtils.isEmpty(stringValue)) {
                return PemKeyEncryption.NONE;
            }

            // We assume that a wrong value, or wrong case is specified
            throw new ConfigurationException("Configuration parameter key.pem.encryption must be PKCS8 or PKCS1");
        }
    }

    @ConfigProperty
    public String getPKCS1EncryptionAlgorithm() {
        return getOptionalValue("key.pem.pkcs1.encryption", "DES-EDE3-CBC", String.class);
    }

    @ConfigProperty
    public String getNameCertificateKeyStore() {
        return getOptionalValue("key.store.certificate.x500name", "CN=localhost", String.class);
    }

    @ConfigProperty
    public String getCertificateSignatureAlgorithm() {
        return getOptionalValue("key.store.signature.algo", "SHA1WithRSA", String.class);
    }

    @ConfigProperty
    public JWSAlgorithm getJWSAlgorithmForRSA() {
        String value = getOptionalValue("jwt.sign.rsa.algo", "RS256", String.class);
        JWSAlgorithm result = null;
        for (JWSAlgorithm algo : RSA_SUPPORTED_ALGOS) {
            if (algo.getName().equals(value)) {
                result = algo;
            }
        }
        if (result == null) {
            throw new ConfigurationException(String.format("Unsupported algorithm name %s for RSA signing", value));
        }
        return result;
    }

    // Java SE Support
    private static JwtSupportConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static JwtSupportConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new JwtSupportConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
