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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class FakeKeyManager implements KeyManager {

    static List<AtbashKey> keys = new ArrayList<>();
    static List<KeyFilter> keyFilters = new ArrayList<>();

    static public void reset() {
        keys.clear();
        keyFilters.clear();
    }

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        List<KeyFilter> filters = selectorCriteria.asKeyFilters();
        keyFilters.addAll(filters);
        return keys;
    }


}
