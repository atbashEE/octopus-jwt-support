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
package be.atbash.ee.security.octopus.keys.selector.filter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 */

public class KeyTypeKeyFilter implements KeyFilter {

    private KeyType keyType;

    public KeyTypeKeyFilter(KeyType keyType) {
        if (keyType == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-110) Key Type to search can't be null.");
        }

        this.keyType = keyType;
    }

    @Override
    public List<AtbashKey> filter(Collection<AtbashKey> keys) {
        if (keys == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-103) List of keys to filter can't be null.");
        }

        List<AtbashKey> result = new ArrayList<>();
        for (AtbashKey key : keys) {
            if (keyType.equals(key.getSecretKeyType().getKeyType())) {
                result.add(key);
            }
        }
        return result;
    }

    @Override
    public String describe() {
        return String.format("KeyFilter{keyType='%s'}", keyType.getValue());
    }
}
