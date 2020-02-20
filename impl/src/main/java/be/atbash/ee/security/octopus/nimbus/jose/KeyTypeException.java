/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jose;

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashException;

import java.security.Key;

public class KeyTypeException extends AtbashException {
    // FIXME We  change it back to extends KeyException when JoseException extends AtbashException

    /**
     * Creates a new key type exception.
     *
     * @param keyType The key type
     * @param action  The action which is performed
     */
    public KeyTypeException(KeyType keyType, String action) {
        super(String.format("Unsupported KeyType %s for %s", keyType.getValue(), action));
    }

    /**
     * Creates a new key type exception.
     *
     * @param expectedAsymmetricPart The expected type of key
     * @param action                 The action which is performed
     */
    public KeyTypeException(AsymmetricPart expectedAsymmetricPart, String action) {
        super(String.format("%s key required for %s", expectedAsymmetricPart.name(), action));
    }

    /**
     * Creates a new key type exception.
     *
     * @param expectedKeyClass The expected key class. Should not be
     *                         {@code null}.
     */
    public KeyTypeException(Class<? extends Key> expectedKeyClass) {

        super(String.format("Invalid key: Must be an instance of %s", expectedKeyClass));
    }

}
