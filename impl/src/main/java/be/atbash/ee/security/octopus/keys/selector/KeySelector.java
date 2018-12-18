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

import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.security.Key;
import java.util.List;

/**
 * Selects a key from the KeyManager based on the SelectorCriteria.
 */
@ApplicationScoped
public class KeySelector {

    private static final Object LOCK = new Object();

    private KeyManager keyManager;

    @PostConstruct
    public void init() {
        keyManager = CDIUtils.retrieveOptionalInstance(KeyManager.class);
    }

    /**
     * @param <T>
     * @return
     */
    public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
        AtbashKey key = selectAtbashKey(selectorCriteria);
        if (key == null) {
            return null;
        }

        return (T) key.getKey();
    }

    public AtbashKey selectAtbashKey(SelectorCriteria selectorCriteria) {
        checkDependencies();

        List<AtbashKey> keys = keyManager.retrieveKeys(selectorCriteria);

        if (keys.isEmpty() || keys.size() > 1) {
            return null;
        }
        return keys.get(0);
    }

    private void checkDependencies() {
        if (keyManager == null) {
            // lazy init, Java SE
            synchronized (LOCK) {
                if (keyManager == null) {

                    keyManager = getKeyManager();
                }
            }
        }
    }

    protected KeyManager getKeyManager() {
        JwtSupportConfiguration configuration = new JwtSupportConfiguration();
        StartupLogging.logConfiguration(configuration);  // Java SE logging

        return configuration.getKeyManager();
    }
}