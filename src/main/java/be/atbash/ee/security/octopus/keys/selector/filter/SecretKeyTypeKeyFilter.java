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
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class SecretKeyTypeKeyFilter implements KeyFilter {

    private SecretKeyType secretKeyType;

    public SecretKeyTypeKeyFilter(SecretKeyType secretKeyType) {
        if (secretKeyType == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-109) Secret Key Type to search can't be null.");
        }

        this.secretKeyType = secretKeyType;
    }

    @Override
    public List<AtbashKey> filter(List<AtbashKey> keys) {
        if (keys == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-103) List of keys to filter can't be null.");
        }

        List<AtbashKey> result = new ArrayList<>();
        for (AtbashKey key : keys) {
            if (secretKeyType.equals(key.getSecretKeyType())) {
                result.add(key);
            }
        }
        return result;
    }
}
