/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.reader.KeyFilesHelper;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.KeyReaderJWKSet;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.inject.Vetoed;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 */
@Vetoed // This seems needed as multiple implementations can be available.
public class LocalKeyManager extends AbstractKeyManager implements KeyManager {

    private static final Object LOCK = new Object();

    private JwtSupportConfiguration configuration;

    private KeyReader keyReader;

    private KeyFilesHelper keyFilesHelper;

    private KeyResourcePasswordLookup passwordLookup;

    private KeyReaderJWKSet keyReaderJWKSet;

    private List<AtbashKey> keys = new ArrayList<>();

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        if (selectorCriteria.getJku() == null) {
            checkKeyLoading();
        }

        return filterKeys(keys, filters);

    }

    private void checkKeyLoading() {
        if (keys.isEmpty()) { // Not as good as keys == null check
            // lazy loading
            synchronized (LOCK) {
                if (keys.isEmpty()) { // Not as good as keys == null check
                    checkDependencies(); // Config driven Password Lookup class

                    String keysLocation = configuration.getKeysLocation();

                    if (StringUtils.isEmpty(keysLocation)) {
                        throw new ConfigurationException("Parameter keys.location is required to have a value");
                    }

                    List<String> keyFiles = keyFilesHelper.determineKeyFiles(keysLocation);
                    for (String keyFile : keyFiles) {
                        keys.addAll(keyReader.readKeyResource(keyFile, passwordLookup));
                    }
                }
            }
        }
    }

    private void checkDependencies() {
        if (configuration == null) {
            // check for null required ??

            configuration = new JwtSupportConfiguration();
            keyReader = new KeyReader();
            keyFilesHelper = new KeyFilesHelper();
            keyReaderJWKSet = new KeyReaderJWKSet();

            passwordLookup = configuration.getPasswordLookup();
        }
    }

    @Override
    public String toString() {
        // For the startup logging.
        return "class " + LocalKeyManager.class.getName();
    }
}
