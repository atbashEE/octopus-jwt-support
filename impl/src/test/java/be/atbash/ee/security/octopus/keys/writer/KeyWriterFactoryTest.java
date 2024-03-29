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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.exception.DuplicateKeyIdException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class KeyWriterFactoryTest {

    private KeyWriterFactory factory;

    @BeforeEach
    public void setup() {
        factory = new KeyWriterFactory();
        factory.init();
    }

    @Test
    public void writeKeyAsJWKSet_duplicateKeyId() {

        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys("kid");

        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID(publicKey.getKeyId())
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        KeyEncoderParameters parameters = new KeyEncoderParameters(jwkSet);

        Assertions.assertThatThrownBy(() -> factory.writeKeyAsJWKSet(atbashKeys.get(1), parameters))
                        .isInstanceOf(DuplicateKeyIdException.class);
    }

    @Test
    public void writeKeyAsJWKSet() {

        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys("kid");

        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID(publicKey.getKeyId())
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        KeyEncoderParameters parameters = new KeyEncoderParameters(jwkSet);


        List<AtbashKey> atbashKeys2 = TestKeys.generateRSAKeys("kid2");

        byte[] bytes = factory.writeKeyAsJWKSet(atbashKeys2.get(0), parameters);
        Assertions.assertThat(bytes).isNotNull();
    }

}