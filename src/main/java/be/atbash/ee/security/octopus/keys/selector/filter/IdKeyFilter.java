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

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class IdKeyFilter implements KeyFilter {

    private String keyId;

    public IdKeyFilter(String keyId) {
        this.keyId = keyId;
    }

    @Override
    public List<AtbashKey> filter(List<AtbashKey> keys) {
        List<AtbashKey> result = new ArrayList<>();
        for (AtbashKey key : keys) {
            if (keyId.equals(key.getKeyId())) {
                result.add(key);
            }
        }
        return result;
    }
}
