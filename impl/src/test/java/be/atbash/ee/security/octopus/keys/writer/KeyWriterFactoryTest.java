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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.exception.DuplicateKeyIdException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class KeyWriterFactoryTest {

    private KeyWriterFactory factory;

    @Before
    public void setup() {
        factory = new KeyWriterFactory();
        factory.init();
    }

    @Test(expected = DuplicateKeyIdException.class)
    public void writeKeyAsJWKSet_duplicateKeyId() {

        List<AtbashKey> atbashKeys = generateRSAKeys("kid");

        AtbashKey publicKey = findPublicKey(atbashKeys);
        AtbashKey privateKey = findPrivateKey(atbashKeys);
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID(publicKey.getKeyId())
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        KeyEncoderParameters parameters = new KeyEncoderParameters(jwkSet);

        factory.writeKeyAsJWKSet(atbashKeys.get(1), parameters);
    }

    @Test
    public void writeKeyAsJWKSet() {

        List<AtbashKey> atbashKeys = generateRSAKeys("kid");

        AtbashKey publicKey = findPublicKey(atbashKeys);
        AtbashKey privateKey = findPrivateKey(atbashKeys);
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID(publicKey.getKeyId())
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        KeyEncoderParameters parameters = new KeyEncoderParameters(jwkSet);


        List<AtbashKey> atbashKeys2 = generateRSAKeys("kid2");
        factory.writeKeyAsJWKSet(atbashKeys2.get(0), parameters);
    }

    private AtbashKey findPublicKey(List<AtbashKey> atbashKeys) {

        // We can use the KeySelector also :)
        return atbashKeys.stream().filter(k -> k.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC).findAny().get();
        // We use immediately .get() since we know there is a public key
    }

    private AtbashKey findPrivateKey(List<AtbashKey> atbashKeys) {

        // We can use the KeySelector also :)
        return atbashKeys.stream().filter(k -> k.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE).findAny().get();
        // We use immediately .get() since we know there is a public key
    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

}