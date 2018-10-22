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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.util.resource.ResourceUtil;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */

public class JWKCreator {

    public static void main(String[] args) {
        KeyReader keyReader = new KeyReader();
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "secp256r1-key.pem", null);

        JWK jwk = createJWK(keys);
        System.out.println(jwk);

    }

    public static JWK createJWK(List<AtbashKey> keys) {
        Set<String> keyIds = new HashSet<>();
        Set<KeyType> keyTypes = new HashSet<>();
        for (AtbashKey key : keys) {
            keyIds.add(key.getKeyId());
            keyTypes.add(key.getSecretKeyType().getKeyType());
        }

        if (keyIds.size() == 1 && keyTypes.size() == 1) {
            return createJWK(keyIds.iterator().next(), keyTypes.iterator().next(), keys);
        }
        return null;
    }

    private static JWK createJWK(String keyId, KeyType keyType, List<AtbashKey> keys) {
        if (KeyType.RSA.equals(keyType)) {
            return createRSAJWK(keyId, keys);
        }
        if (KeyType.EC.equals(keyType)) {
            return createECJWK(keyId, keys);
        }
        return null;
    }

    private static JWK createRSAJWK(String keyId, List<AtbashKey> keys) {
        RSAPrivateKey privateKey = null;
        PublicKey publicKey = null;

        for (AtbashKey key : keys) {
            if (AsymmetricPart.PUBLIC == key.getSecretKeyType().getAsymmetricPart()) {
                publicKey = (PublicKey) key.getKey();
            }
            if (AsymmetricPart.PRIVATE == key.getSecretKeyType().getAsymmetricPart()) {
                privateKey = (RSAPrivateKey) key.getKey();
            }
        }

        // FIXME Check to see if we have private and public key.
        return new RSAKey.Builder((RSAPublicKey) publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

    private static JWK createECJWK(String keyId, List<AtbashKey> keys) {
        ECPrivateKey privateKey = null;
        PublicKey publicKey = null;

        for (AtbashKey key : keys) {
            if (AsymmetricPart.PUBLIC == key.getSecretKeyType().getAsymmetricPart()) {
                publicKey = (PublicKey) key.getKey();
            }
            if (AsymmetricPart.PRIVATE == key.getSecretKeyType().getAsymmetricPart()) {
                privateKey = (ECPrivateKey) key.getKey();
            }
        }

        // FIXME Check to see if we have private and public key.
        return new ECKey.Builder(ECCurveHelper.getCurve(privateKey), (ECPublicKey) publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

}
