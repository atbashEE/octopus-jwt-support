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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ServiceLoader;
import java.util.Timer;
import java.util.TimerTask;

/**
 *
 */

@ModuleConfigName("Octopus JCA Configuration")
//  Java Cryptography Architecture
public class JCASupportConfiguration extends AbstractConfiguration implements ModuleConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(JCASupportConfiguration.class);

    private static final Object SECURE_RANDOM_LOCK = new Object();

    private SecureRandom secureRandom;

    private TimerTask task;

    @ConfigEntry
    public String getSecureRandomAlgorithm() {
        return getOptionalValue("jwt.jca.securerandom.algo", String.class);
    }

    @ConfigEntry
    public SecureRandom getSecureRandom() {
        synchronized (SECURE_RANDOM_LOCK) {
            if (secureRandom == null) {
                tryServiceLoader();
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
            }
            // Do we need to recreate the Secure Random after x seconds of usage?
            Integer secureRandomRecreateSeconds = getSecureRandomRecreateSeconds();
            if (secureRandomRecreateSeconds != 0 && task == null) {
                long recreatePeriod = secureRandomRecreateSeconds * 1000L;
                task = new TimerTask() {
                    public void run() {
                        synchronized (SECURE_RANDOM_LOCK) {
                            // reset variable so that SecureRandom is recreated next time.
                            secureRandom = null;
                        }
                    }
                };
                new Timer("Task to recreate SecureRandom").scheduleAtFixedRate(task, recreatePeriod, recreatePeriod);
            }
        }
        return secureRandom;
    }

    private void tryServiceLoader() {
        ServiceLoader<SecureRandomProvider> loader = ServiceLoader.load(SecureRandomProvider.class);
        for (SecureRandomProvider provider : loader) {
            if (secureRandom != null) {
                LOGGER.warn("Service loader for 'SecureRandomProvider' returned multiple providers. The selected provider may be different next time.");
                break;
            }
            secureRandom = provider.get();
        }
    }

    @ConfigEntry
    public Integer getSecureRandomRecreateSeconds() {
        return getOptionalValue("jwt.jca.securerandom.recreate", 0, Integer.class);
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
