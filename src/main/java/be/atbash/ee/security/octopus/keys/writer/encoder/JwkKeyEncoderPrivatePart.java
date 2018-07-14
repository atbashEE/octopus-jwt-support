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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */

public class JwkKeyEncoderPrivatePart implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) getPublicKey(atbashKey.getKey())).keyID(atbashKey.getKeyId())
                .privateKey((RSAPrivateKey) atbashKey.getKey())
                .build();

        return rsaKey.toJSONObject().toJSONString().getBytes("UTF-8");

    }

    private PublicKey getPublicKey(Key key) {
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) key;

            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            try {
                // FIXME What about EC ??
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                return keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {
                throw new AtbashUnexpectedException(e);
            }
        } else {
            throw new UnsupportedOperationException("TODO");
        }
    }
}
