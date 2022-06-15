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
package be.atbash.ee.security.octopus.nimbus;

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;

import java.util.StringJoiner;

public enum KeyFamily {

    RSA_PUBLIC(KeyType.RSA, AsymmetricPart.PUBLIC),
    RSA_PRIVATE(KeyType.RSA, AsymmetricPart.PRIVATE),
    EC_PUBLIC(KeyType.EC, AsymmetricPart.PUBLIC),
    EC_PRIVATE(KeyType.EC, AsymmetricPart.PRIVATE),
    AES(KeyType.OCT, AsymmetricPart.SYMMETRIC),
    OKP_PUBlIC(KeyType.OKP, AsymmetricPart.PUBLIC),
    OKP_PRIVATE(KeyType.OKP, AsymmetricPart.PRIVATE),

    // TODO What about DH keys. Can they be in JWK and should we add them here?
    ;

    private final KeyType keyType;
    private final AsymmetricPart asymmetricPart;

    KeyFamily(KeyType keyType, AsymmetricPart asymmetricPart) {
        this.keyType = keyType;
        this.asymmetricPart = asymmetricPart;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public AsymmetricPart getAsymmetricPart() {
        return asymmetricPart;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", KeyFamily.class.getSimpleName() + "[", "]")
                .add("keyType=" + keyType)
                .add("asymmetricPart=" + asymmetricPart)
                .toString();
    }
}
