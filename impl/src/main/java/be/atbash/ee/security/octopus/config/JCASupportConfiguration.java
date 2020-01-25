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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 */

@ModuleConfigName("Octopus JCA Configuration")
//  Java Cryptography Architecture
public class JCASupportConfiguration extends AbstractConfiguration implements ModuleConfig {

    private static final Object SECURE_RANDOM_LOCK = new Object();

    private SecureRandom secureRandom;

    @ConfigEntry
    public String getSecureRandomAlgorithm() {
        return getOptionalValue("jwt.jca.securerandom.algo", String.class);
    }

    @ConfigEntry
    public SecureRandom getSecureRandom() {
        synchronized (SECURE_RANDOM_LOCK) {
            if (secureRandom == null) {
                String algo = getSecureRandomAlgorithm();
                if (StringUtils.isEmpty(algo)) {
                    secureRandom = new SecureRandom();
                } else {
                    try {
                        secureRandom = SecureRandom.getInstance(algo, BouncyCastleProviderSingleton.getInstance());
                    } catch (NoSuchAlgorithmException e) {
                       throw new ConfigurationException(e.getMessage());
                    }
                }
            }
            // FIXME Do we need a Thread which does the reseed every now and then
            //secureRandom.setSeed(secureRandom.generateSeed());
        }
        return secureRandom;
    }

    // Java SE Support
    private static JCASupportConfiguration INSTANCE;

    public static synchronized JCASupportConfiguration getInstance() {
        // Synchronize methods are not so bad for performance anymore and since only 1 synchronized static there are no side effects
        if (INSTANCE == null) {
            INSTANCE = new JCASupportConfiguration();
            if (!CDICheck.withinContainer()) {
                StartupLogging.logConfiguration(INSTANCE);
            }
        }
        return INSTANCE;
    }

}
