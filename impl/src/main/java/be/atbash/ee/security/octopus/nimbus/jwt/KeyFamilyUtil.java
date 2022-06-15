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
package be.atbash.ee.security.octopus.nimbus.jwt;

import be.atbash.ee.security.octopus.nimbus.KeyFamily;
import be.atbash.util.PublicAPI;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@PublicAPI
public final class KeyFamilyUtil {

    public static final KeyFamilyUtil INSTANCE = new KeyFamilyUtil();
    private KeyFamilyUtil() {
    }

    public KeyFamily determineKeyFamily(Key secretKey) {
        KeyFamily result = null;
        if (secretKey instanceof RSAPublicKey) {
            result = KeyFamily.RSA_PUBLIC;
        }
        if (secretKey instanceof RSAPrivateKey) {
            result = KeyFamily.RSA_PRIVATE;
        }
        if (secretKey instanceof ECPublicKey) {
            result = KeyFamily.EC_PUBLIC;
        }
        if (secretKey instanceof ECPrivateKey) {
            result = KeyFamily.EC_PRIVATE;
        }
        if (secretKey instanceof SecretKey) {
            result = KeyFamily.AES;
        }
        if (secretKey instanceof BCEdDSAPublicKey) {
            result = KeyFamily.OKP_PUBlIC;
        }
        if (secretKey instanceof BCEdDSAPrivateKey) {
            result = KeyFamily.OKP_PRIVATE;
        }
        return result;
    }
}
