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
package be.atbash.ee.security.octopus.nimbus.jose;

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;

import java.security.Key;
import java.util.Arrays;

public class KeyTypeException extends JOSEException {

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

    /**
     * Creates a new key type exception.
     *
     * @param expectedKeyInterface The expected key interfaces. Should not
     *                             be {@code null}.
     * @param additionalInterfaces Additional interfaces the key is required to implement.
     */
    public KeyTypeException(Class<? extends Key> expectedKeyInterface, Class<?>... additionalInterfaces) {

        super(String.format("Invalid key: Must be an instance of %s and implement all of the following interfaces %s",
                expectedKeyInterface, Arrays.toString(additionalInterfaces)));
    }
}
