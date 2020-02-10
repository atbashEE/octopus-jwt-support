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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


public class RSAKeyUtilsTest {

    @Test
    public void testConversion_ok() throws JOSEException {

        RSAKey rsaJWK = generateKey();

        RSAPrivateKey privateKey = (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey(rsaJWK);

        assertThat(privateKey.getModulus().bitLength()).isEqualTo(2048);
        assertThat(rsaJWK.toRSAPrivateKey()).isNotNull();

        assertThat(rsaJWK.toRSAPrivateKey().getEncoded()).isEqualTo(privateKey.getEncoded());
    }

    @Test
    public void testConversion_missing() {

        RSAKey rsaJWK = generateKey().toPublicJWK();

        JOSEException e = Assertions.assertThrows(JOSEException.class,
                () -> RSAKeyUtils.toRSAPrivateKey(rsaJWK));

        assertThat(e.getMessage()).isEqualTo("The RSA JWK doesn't contain a private part");

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
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys("kid");

        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);

        return new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid")
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .build();


    }
}
