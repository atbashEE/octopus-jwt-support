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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.exception.MissingPasswordLookupException;
import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyReaderKeyStoreTest {

    @Test
    void readResource() {
        KeyReaderKeyStore keyStore = new KeyReaderKeyStore();
        ResourceNotFoundException notFoundException = assertThrows(ResourceNotFoundException.class, () -> keyStore.readResource("./non-existing.path", new TestPasswordLookup()));
        assertThat(notFoundException.getMessage()).isEqualTo("Path not found : ./non-existing.path");
    }

    @Test
    void readResource_nolookup() {
        KeyReaderKeyStore keyStore = new KeyReaderKeyStore();
        MissingPasswordLookupException missingException = assertThrows(MissingPasswordLookupException.class, () -> keyStore.readResource("./some.path", null));
        assertThat(missingException.getMessage()).isEqualTo("KeyResourcePasswordLookup instance required");
    }
}