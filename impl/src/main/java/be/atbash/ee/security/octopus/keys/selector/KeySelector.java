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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.util.CDIUtils;
import be.atbash.util.PublicAPI;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.security.Key;
import java.util.List;

/**
 * Selects a key from the KeyManager based on the SelectorCriteria.
 */
@ApplicationScoped
@PublicAPI
public class KeySelector {

    private KeyManager keyManager;

    public KeySelector() {
    }

    public KeySelector(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @PostConstruct
    public void init() {
        // CDI Version, so the no-op constructor is used. or programmatic and keyManager not explicitly set.
        keyManager = CDIUtils.retrieveOptionalInstance(KeyManager.class);
    }

    /**
     * Select the Cryptographic key from the Key Manager based on the Criteria. Return null when no key or multiple
     * matching keys are found.
     * @param selectorCriteria Criteria for the key selection.
     * @param <T> Subtype of Key which needs to be returned.
     * @return The Cryptographic key or null when no key or multiple keys matches.
     */
    public <T extends Key> T selectSecretKey(SelectorCriteria selectorCriteria) {
        AtbashKey key = selectAtbashKey(selectorCriteria);
        if (key == null) {
            return null;
        }

        return (T) key.getKey();
    }

    /**
     * Select the AtbashKey from the Key Manager based on the Criteria. Return null when no key or multiple
     * matching keys are found.
     * @param selectorCriteria Criteria for the key selection.
     * @return The Atbash Key or null when no key or multiple keys matches.
     */
    public AtbashKey selectAtbashKey(SelectorCriteria selectorCriteria) {
        checkDependencies();

        List<AtbashKey> keys = keyManager.retrieveKeys(selectorCriteria);

        if (keys.size() != 1) {
            return null;
        }
        return keys.get(0);
    }

    private synchronized void checkDependencies() {
        if (keyManager == null) {
            // lazy init, Java SE
            keyManager = getKeyManager();
        }
    }

    protected KeyManager getKeyManager() {
        JwtSupportConfiguration configuration = JwtSupportConfiguration.getInstance();
        return configuration.getKeyManager();
    }
}