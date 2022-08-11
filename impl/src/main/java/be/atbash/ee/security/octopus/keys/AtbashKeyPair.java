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
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.keys.selector.filter.IdKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extracts a KeyPair from a Collection of AtbashKeys.
 */
public class AtbashKeyPair {

    private final KeyPair keyPair;


    public AtbashKeyPair(Collection<AtbashKey> keys, String kid) {
        this(new IdKeyFilter(kid).filter(keys));
    }

    public AtbashKeyPair(Collection<AtbashKey> keys) {
        validateKeyTypeAndId(keys);
        PrivateKey privateKey = findPrivateKey(keys);
        PublicKey publicKey = findPublicKey(keys);
        keyPair = new KeyPair(publicKey, privateKey);
    }

    private PrivateKey findPrivateKey(Collection<AtbashKey> keys) {
        List<AtbashKey> atbashKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        if (atbashKeys.size() > 1) {
            throw new NotSingleKeyException(AsymmetricPart.PRIVATE);
        }
        PrivateKey result = null;
        if (!atbashKeys.isEmpty()) {
            result = (PrivateKey) atbashKeys.get(0).getKey();
        }
        return result;
    }

    private PublicKey findPublicKey(Collection<AtbashKey> keys) {
        List<AtbashKey> atbashKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        if (atbashKeys.size() > 1) {
            throw new NotSingleKeyException(AsymmetricPart.PUBLIC);
        }
        PublicKey result = null;
        if (!atbashKeys.isEmpty()) {
            result = (PublicKey) atbashKeys.get(0).getKey();
        }
        return result;
    }

    private void validateKeyTypeAndId(Collection<AtbashKey> keys) {
        Set<String> ids = new HashSet<>();
        Set<KeyType> types = new HashSet<>();

        for (AtbashKey key : keys) {
            ids.add(key.getKeyId());
            types.add(key.getSecretKeyType().getKeyType());
        }
        if (ids.size() != 1 || types.size() != 1) {
            throw new NotSingleKeyException(ids, types);
        }
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
