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
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.selector.filter.*;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.ClassUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

/**
 * Selects a key from the KeyManager based on the SelectorCriteria.
 */
@ApplicationScoped
public class KeySelector {

    private static final Object LOCK = new Object();

    private static final Logger LOGGER = LoggerFactory.getLogger(KeySelector.class);

    private KeyManager keyManager;

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
        retrieveKeyManager();

        List<KeyFilter> filters = new ArrayList<>();
        if (StringUtils.hasText(selectorCriteria.getId())) {
            filters.add(new IdKeyFilter(selectorCriteria.getId()));
        }
        if (selectorCriteria.getSecretKeyType() != null) {
            filters.add(new SecretKeyTypeKeyFilter(selectorCriteria.getSecretKeyType()));
        }
        if (selectorCriteria.getKeyType() != null) {
            filters.add(new KeyTypeKeyFilter(selectorCriteria.getKeyType()));
        }
        if (selectorCriteria.getAsymmetricPart() != null) {
            filters.add(new AsymmetricPartKeyFilter(selectorCriteria.getAsymmetricPart()));
        }

        List<AtbashKey> keys = keyManager.retrieveKeys(filters);

        if (keys.isEmpty()) {
            LOGGER.warn("(OCT-KEY-010) No key found for criteria"); // FIXME log selectorCriteria
            return null;
        }
        if (keys.size() > 1) {
            LOGGER.warn("(OCT-KEY-011) Multiple keys found for criteria"); // FIXME log selectorCriteria
            return null;
        }
        return keys.get(0);
    }

    private void retrieveKeyManager() {
        if (keyManager == null) {
            // lazy init
            synchronized (LOCK) {
                if (keyManager == null) {

                    JwtSupportConfiguration configuration = new JwtSupportConfiguration();
                    StartupLogging.logConfiguration(configuration);  // Java SE logging

                    keyManager = ClassUtils.newInstance(configuration.getKeyManagerClass());
                }
            }
        }
    }
}