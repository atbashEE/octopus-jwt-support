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
package be.atbash.ee.security.octopus.keys.selector.filter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 */

public class IdKeyFilter implements KeyFilter {

    private String keyId;

    public IdKeyFilter(String keyId) {
        if (StringUtils.isEmpty(keyId)) {
            throw new AtbashIllegalActionException("(OCT-DEV-102) Key Id to search can't be null or empty");
        }
        this.keyId = keyId;
    }

    @Override
    public List<AtbashKey> filter(Collection<AtbashKey> keys) {
        if (keys == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-103) List of keys to filter can't be null");
        }
        List<AtbashKey> result = new ArrayList<>();
        for (AtbashKey key : keys) {
            if (keyId.equals(key.getKeyId())) {
                result.add(key);
            }
        }
        return result;
    }

    public String getKeyId() {
        return keyId;
    }

    @Override
    public String describe() {
        return String.format("KeyFilter{keyId='%s'}", keyId);
    }
}
