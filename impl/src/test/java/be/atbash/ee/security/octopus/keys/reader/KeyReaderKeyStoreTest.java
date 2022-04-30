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
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Scanner;

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

    @Test
    void parseContent() throws IOException {
        InputStream inputStream = KeyReaderKeyStoreTest.class.getResourceAsStream("/keystore.jks.b64");
        assertThat(inputStream).isNotNull();
        String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();
        inputStream.close();

        KeyReaderKeyStore keyStore = new KeyReaderKeyStore();
        KeyResourcePasswordLookup lookup = new TestPasswordLookup("atbash".toCharArray());
        List<AtbashKey> keys = keyStore.parseContent(fileContent, lookup);

        assertThat(keys).hasSize(2);
        AtbashKey atbashKey = keys.get(0);
        assertThat(atbashKey.getKeyId()).isEqualTo("thealias");
        // Private part is added first
        assertThat(atbashKey.getSecretKeyType()).isEqualTo(new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE));

        atbashKey = keys.get(1);
        assertThat(atbashKey.getKeyId()).isEqualTo("thealias");
        // Public part is added second
        assertThat(atbashKey.getSecretKeyType()).isEqualTo(new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC));

    }

}