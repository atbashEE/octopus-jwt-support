/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.generator.DHGenerationParameters;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.KeyType;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

/**
 *
 */

public class SecretKeyType {

    private KeyType keyType;
    private AsymmetricPart asymmetricPart;

    public SecretKeyType(KeyType keyType) {
        this(keyType, AsymmetricPart.SYMMETRIC);
    }

    public SecretKeyType(KeyType keyType, AsymmetricPart asymmetricPart) {
        if (keyType == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-107) Parameter KeyType can't be null");
        }
        if (keyType == KeyType.OCT) {
            if (asymmetricPart != AsymmetricPart.SYMMETRIC) {
                throw new AtbashIllegalActionException("(OCT-DEV-109) AsymmetricPart can't be specified for a symmetric key type");
            }
        } else {

            if (asymmetricPart == null || asymmetricPart == AsymmetricPart.SYMMETRIC) {
                throw new AtbashIllegalActionException("(OCT-DEV-108) Parameter AsymmetricPart is required for a asymmetric key type");
            }
        }
        this.keyType = keyType;
        this.asymmetricPart = asymmetricPart;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public AsymmetricPart getAsymmetricPart() {
        return asymmetricPart;
    }

    public boolean isAsymmetric() {
        return asymmetricPart != null && asymmetricPart != AsymmetricPart.SYMMETRIC;
    }

    public boolean isPrivate() {
        return (isAsymmetric() && asymmetricPart == AsymmetricPart.PRIVATE);
    }

    public static SecretKeyType fromKey(Key key) {
        SecretKeyType result = null;
        if (key instanceof RSAKey) {
            result = new SecretKeyType(KeyType.RSA, determineAsymmetricPart(key));
        }
        if (key instanceof ECKey) {
            result = new SecretKeyType(KeyType.EC, determineAsymmetricPart(key));
        }
        if (key instanceof SecretKey) {  // for HMAC
            result = new SecretKeyType(KeyType.OCT);
        }
        if (key instanceof DHKey) {
            result = new SecretKeyType(DHGenerationParameters.DH, determineAsymmetricPart(key));
        }
        // FIXME OCTKEY (Edwards EC Key)
        // OCTKEY https://tools.ietf.org/html/rfc8037
        /*
        Octet key pair (OKP)
This key type is used by the EdDSA algorithms.

signature with curves Ed25519 and Ed448
encryption with curves X25519 nd X448
At the moment, only Ed25519 and X25519 curves are supported.

Public keys must contain crv (curve) and x values. Private keys will also contain a value d.

see com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
         */
        if (result == null) {
            throw new IllegalArgumentException(String.format("Unsupported Key instance %s", key.getClass().getName()));
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SecretKeyType)) {
            return false;
        }

        SecretKeyType that = (SecretKeyType) o;

        if (!keyType.equals(that.keyType)) {
            return false;
        }
        return asymmetricPart == that.asymmetricPart;
    }

    @Override
    public int hashCode() {
        int result = keyType.hashCode();
        result = 31 * result + (asymmetricPart != null ? asymmetricPart.hashCode() : 0);
        return result;
    }

    private static AsymmetricPart determineAsymmetricPart(Key key) {
        return key instanceof PrivateKey ? AsymmetricPart.PRIVATE : AsymmetricPart.PUBLIC;
    }
}
