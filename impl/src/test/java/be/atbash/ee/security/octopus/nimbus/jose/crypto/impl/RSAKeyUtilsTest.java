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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class RSAKeyUtilsTest {

    @Test
    public void testConversion_ok() throws JOSEException {

        RSAKey rsaJWK = generateKey();

        RSAPrivateKey privateKey = (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey(rsaJWK);

        assertThat(privateKey.getModulus().bitLength()).isEqualTo(2048);

        Assert.assertArrayEquals(privateKey.getEncoded(), rsaJWK.toRSAPrivateKey().getEncoded());
    }

    @Test
    public void testConversion_missing() {

        RSAKey rsaJWK = generateKey().toPublicJWK();

        try {
            RSAKeyUtils.toRSAPrivateKey(rsaJWK);
            fail();
        } catch (JOSEException e) {
            assertThat(e.getMessage()).isEqualTo("The RSA JWK doesn't contain a private part");
        }
    }

    @Test
    public void testKeyLength_known() throws JOSEException {

        RSAKey rsaJWK = generateKey();

        assertThat(RSAKeyUtils.keyBitLength(rsaJWK.toPrivateKey())).isEqualTo(2048);
    }

    @Test
    // PKCS#11
    public void testKeyLength_notKnown_privateKeyNotRSAPrivateKeyInstance() {

        PrivateKey privateKey = new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }


            @Override
            public String getFormat() {
                return null;
            }


            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        assertThat(RSAKeyUtils.keyBitLength(privateKey)).isEqualTo(-1);
    }

    @Test
    // PKCS#11
    public void testKeyLength_notKnown_rsaPrivateKey_getModulusThrowsException() {

        PrivateKey rsaPrivateKey = new RSAPrivateKey() {
            @Override
            public BigInteger getPrivateExponent() {
                return null;
            }


            @Override
            public String getAlgorithm() {
                return "RSA";
            }


            @Override
            public String getFormat() {
                return null;
            }


            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }


            @Override
            public BigInteger getModulus() {
                throw new RuntimeException("Operation not supported");
            }
        };

        assertThat(RSAKeyUtils.keyBitLength(rsaPrivateKey)).isEqualTo(-1);
    }

    private RSAKey generateKey() {
        KeyGenerator keyGenerator = new KeyGenerator();
        keyGenerator.init();
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeySize(2048)
                .withKeyId("kid")
                .build();
        List<AtbashKey> atbashKeys = keyGenerator.generateKeys(generationParameters);

        ListKeyManager keyManager = new ListKeyManager(atbashKeys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> privateList = keyManager.retrieveKeys(criteria);

        AtbashKey privateKey = privateList.get(0);
        criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PUBLIC).build();

        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);
        AtbashKey publicKey = publicList.get(0);


        return new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid")
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();


    }
}
