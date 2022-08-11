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

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashException;

import java.util.Set;

public class NotSingleKeyException extends AtbashException {

    public NotSingleKeyException(Set<String> ids, Set<KeyType> types) {
        super(String.format("Collection contained not a single type or keys with same id. ids = %s, types = %s", ids, types));
    }

    public NotSingleKeyException(AsymmetricPart asymmetricPart) {
        super(String.format("Collection contained not a single key of type %s.", asymmetricPart.toString()));
    }
}
