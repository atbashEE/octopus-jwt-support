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
package be.atbash.ee.security.octopus.keys;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.keys.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.reader.KeyFilesHelper;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Vetoed;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@Vetoed // This seems needed as multiple implementations can be available.
// But why are we then using @Inject since we always use instantiation by new?
public class LocalKeyManager implements KeyManager {

    private static final Object LOCK = new Object();

    @Inject
    private JwtSupportConfiguration configuration;

    @Inject
    private KeyReader keyReader;

    @Inject
    private KeyFilesHelper keyFilesHelper;

    private KeyResourcePasswordLookup passwordLookup;

    private List<AtbashKey> keys;

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        checkKeyLoading();

        List<AtbashKey> result = new ArrayList<>(keys);
        for (KeyFilter filter : filters) {
            result = filter.filter(result);
        }

        return result;

    }

    private void checkKeyLoading() {
        if (keys == null) {
            // lazy loading
            synchronized (LOCK) {
                if (keys == null) {
                    checkDependencies(); // Support java SE + Config driven Password Lookup class

                    String keysLocation = configuration.getKeysLocation();

                    if (StringUtils.isEmpty(keysLocation)) {
                        throw new ConfigurationException("Parameter keys.location is required to have a value");
                    }

                    List<String> keyFiles = keyFilesHelper.determineKeyFiles(keysLocation);
                    keys = new ArrayList<>();
                    for (String keyFile : keyFiles) {
                        keys.addAll(keyReader.readKeyResource(keyFile, passwordLookup));
                    }
                }
            }
        }
    }

    private void checkDependencies() {
        if (configuration == null) {
            // Java SE
            configuration = new JwtSupportConfiguration();
            keyReader = new KeyReader();
            keyFilesHelper = new KeyFilesHelper();
        }
        if (passwordLookup == null) {
            passwordLookup = configuration.getPasswordLookup();
        }
    }

    @Override
    public String toString() {
        // For the startup logging.
        return "class " + LocalKeyManager.class.getName();
    }
}
