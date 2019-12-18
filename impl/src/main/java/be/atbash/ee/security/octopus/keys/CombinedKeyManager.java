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

import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;

import javax.enterprise.inject.Vetoed;
import java.util.List;

@Vetoed
public class CombinedKeyManager extends AbstractKeyManager implements KeyManager {

    private LocalKeyManager localKeyManager = new LocalKeyManager();

    private RemoteKeyManager remoteKeyManager = new RemoteKeyManager();

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        List<AtbashKey> atbashKeys = localKeyManager.retrieveKeys(selectorCriteria);
        if (atbashKeys.isEmpty()) {
            atbashKeys = remoteKeyManager.retrieveKeys(selectorCriteria);
        }
        return atbashKeys;
    }
}
