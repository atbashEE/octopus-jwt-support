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

import be.atbash.ee.security.octopus.keys.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.reflection.ClassUtils;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class LocalKeyManager implements KeyManager {

    private static final Object LOCK = new Object();

    @Inject
    private JwtSupportConfiguration configuration;

    @Inject
    private KeyReader keyReader;

    private KeyResourcePasswordLookup passwordLookup;

    private List<AtbashKey> keys;

    public List<AtbashKey> retrieveKeys(List<KeyFilter> filters) {
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
                    // FIXME use KeyFilesHelper to read all files within directory.
                    keys = keyReader.readKeyResource(configuration.getKeysLocation(), passwordLookup);
                }
            }
        }
    }

    private void checkDependencies() {
        if (configuration == null) {
            // Java SE
            configuration = new JwtSupportConfiguration();
            keyReader = new KeyReader();
        }
        if (passwordLookup == null) {
            passwordLookup = ClassUtils.newInstance(configuration.getPasswordLookupClass());
        }
    }
}
