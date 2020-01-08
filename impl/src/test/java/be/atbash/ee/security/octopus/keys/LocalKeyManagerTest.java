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
package be.atbash.ee.security.octopus.keys;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPrivate;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPublic;
import be.atbash.ee.security.octopus.keys.reader.KeyFilesHelper;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class LocalKeyManagerTest {

    @Mock
    private JwtSupportConfiguration configurationMock;

    @Mock
    private KeyReader keyReaderMock;

    @Mock
    private KeyFilesHelper keyFilesHelperMock;

    @Mock
    private KeyResourcePasswordLookup keyResourcePasswordLookupMock;

    @InjectMocks
    private LocalKeyManager localKeyManager;

    @Test
    public void testKeyLocations() {
        when(configurationMock.getKeysLocation()).thenReturn("");
        Assertions.assertThrows(ConfigurationException.class, () -> localKeyManager.retrieveKeys(SelectorCriteria.newBuilder().build()));
    }

    @Test
    public void retrieveKeys() {

        when(configurationMock.getKeysLocation()).thenReturn("keyLocation");
        List<String> keys = new ArrayList<>();
        keys.add("key1");
        keys.add("key2");
        when(keyFilesHelperMock.determineKeyFiles(anyString())).thenReturn(keys);

        doReturn(Collections.singletonList(new AtbashKey("kid2", new FakeRSAPrivate()))).when(keyReaderMock).readKeyResource("key1", keyResourcePasswordLookupMock);
        doReturn(Collections.singletonList(new AtbashKey("kid1", new FakeRSAPublic()))).when(keyReaderMock).readKeyResource("key2", keyResourcePasswordLookupMock);

        SelectorCriteria.Builder builder = SelectorCriteria.newBuilder();
        builder.withId("kid1");
        List<AtbashKey> filteredKeys = localKeyManager.retrieveKeys(builder.build());
        assertThat(filteredKeys).hasSize(1);

        assertThat(filteredKeys.get(0).getSecretKeyType().getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
    }

    @Test
    public void retrieveKeys_multipleFilters() {

        when(configurationMock.getKeysLocation()).thenReturn("keyLocation");
        List<String> keys = new ArrayList<>();
        keys.add("key1");
        keys.add("key2");
        when(keyFilesHelperMock.determineKeyFiles(anyString())).thenReturn(keys);

        doReturn(Collections.singletonList(new AtbashKey("kid1", new FakeRSAPrivate()))).when(keyReaderMock).readKeyResource("key1", keyResourcePasswordLookupMock);
        doReturn(Collections.singletonList(new AtbashKey("kid1", new FakeRSAPublic()))).when(keyReaderMock).readKeyResource("key2", keyResourcePasswordLookupMock);

        SelectorCriteria.Builder builder = SelectorCriteria.newBuilder();
        builder.withId("kid1");
        builder.withAsymmetricPart(AsymmetricPart.PUBLIC);

        List<AtbashKey> filteredKeys = localKeyManager.retrieveKeys(builder.build());
        assertThat(filteredKeys).hasSize(1);

        assertThat(filteredKeys.get(0).getSecretKeyType().getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
    }

    @Test
    public void retrieveKeys_keepOriginalKeyList() {

        when(configurationMock.getKeysLocation()).thenReturn("keyLocation");
        List<String> keys = new ArrayList<>();
        keys.add("key1");
        keys.add("key2");
        when(keyFilesHelperMock.determineKeyFiles(anyString())).thenReturn(keys);

        doReturn(Collections.singletonList(new AtbashKey("kid2", new FakeRSAPrivate()))).when(keyReaderMock).readKeyResource("key1", keyResourcePasswordLookupMock);
        doReturn(Collections.singletonList(new AtbashKey("kid1", new FakeRSAPublic()))).when(keyReaderMock).readKeyResource("key2", keyResourcePasswordLookupMock);

        SelectorCriteria.Builder builder = SelectorCriteria.newBuilder();
        builder.withId("kid1");

        List<AtbashKey> filteredKeys = localKeyManager.retrieveKeys(builder.build());

        assertThat(filteredKeys).hasSize(1);

        assertThat(filteredKeys.get(0).getSecretKeyType().getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);

        // Now see if localKeyManager still has the list of all keys and that we can filter it on something else
        builder = SelectorCriteria.newBuilder();
        builder.withAsymmetricPart(AsymmetricPart.PRIVATE);

        filteredKeys = localKeyManager.retrieveKeys(builder.build());
        assertThat(filteredKeys).hasSize(1);

        assertThat(filteredKeys.get(0).getSecretKeyType().getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);
    }

    @Test
    public void retrieveKeys_nullParameterNotAllowed() {

        Assertions.assertThrows(AtbashIllegalActionException.class, () -> localKeyManager.retrieveKeys(null));
    }
}