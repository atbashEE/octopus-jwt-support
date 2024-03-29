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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Vetoed;
import java.util.ArrayList;
import java.util.List;

@Vetoed
@PublicAPI
public class ListKeyManager implements KeyManager {

    private final List<AtbashKey> keys;

    public ListKeyManager(List<AtbashKey> keys) {
        this.keys = keys;
    }

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        List<AtbashKey> result = new ArrayList<>(keys);
        for (KeyFilter filter : filters) {
            result = filter.filter(result);
        }

        return result;
    }
}
