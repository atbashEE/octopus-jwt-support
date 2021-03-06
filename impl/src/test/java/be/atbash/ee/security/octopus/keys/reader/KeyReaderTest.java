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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.util.resource.ResourceUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeyReaderTest {

    private KeyReader keyReader = new KeyReader();

    @AfterEach
    public void tearDown() {
        TestConfig.resetConfig();
    }

    @Test
    public void readKeyResource_scenario1() {
        // RSA PKCS#1 format

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pk.pem", new TestPasswordLookup("atbash".toCharArray()));
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("rsa.pk");  // filename without extension
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario2() {
        // RSA public key
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pub.pem");

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getKeyId()).isEqualTo("rsa.pub");  // filename without extension
        assertThat(keys.get(0).getKey()).isInstanceOf(RSAPublicKey.class);
    }

    @Test
    @Disabled
    // OpenSSL generated output ( isn't working javax.crypto.BadPaddingException: pad block corrupted)
    // Also XCA exported file isn't working
    public void readKeyResource_scenario3() {
        // RSA  PKCS#8 format

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pkcs8.pem", new TestPasswordLookup("atbash8".toCharArray()));

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getKeyId()).isEqualTo("authentication.pkcs8");  // filename without extension
        assertThat(keys.get(0).getKey()).isInstanceOf(RSAPrivateKey.class);

    }

    @Test
    public void readKeyResource_scenario4() {
        // EC PKCS#1 format

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "secp256r1-key-aes.pem", new TestPasswordLookup("atbash".toCharArray()));
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("secp256r1-key-aes");  // filename without extension
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario5() {
        // EC public key
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "ecpubkey.pem");

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getKeyId()).isEqualTo("ecpubkey");  // filename without extension
        assertThat(keys.get(0).getKey()).isInstanceOf(ECPublicKey.class);
    }

    @Test
    public void readKeyResource_scenario6() {
        // EC  PKCS#8 format

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "ec.pkcs8.pem", new TestPasswordLookup("atbash8".toCharArray()));

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getKeyId()).isEqualTo("ec.pkcs8");  // filename without extension
        assertThat(keys.get(0).getKey()).isInstanceOf(ECPrivateKey.class);

    }

    @Test
    public void readKeyResource_scenario7() {
        // RSA JWK

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk");
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("rsa.pk.free");  // kid from within JWK
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario8() {
        // EC JWK

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "ec.jwk");
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("secp256r1-key");  // kid from within JWK
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario9() {
        // RSA JWK encrypted

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwke", new TestPasswordLookup(null, "atbash".toCharArray()));
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("rsa.pk.free");  // kid from within JWK
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario10() {
        // RSA JWK encrypted

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "ec.jwke", new TestPasswordLookup(null, "atbash".toCharArray()));
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("secp256r1-key");  // kid from within JWK
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(ECPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario11() {
        // JWKSet (RSA + EC)

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "test.jwkset", new TestPasswordLookup(null, "atbash".toCharArray()));
        assertThat(keys).hasSize(4);

        Set<String> data = new HashSet<>();
        for (int i = 0; i < 4; i++) {

            AtbashKey atbashKey = keys.get(i);

            data.add(atbashKey.getKeyId() + " - " + atbashKey.getSecretKeyType().getKeyType().getValue() + " - " + atbashKey.getSecretKeyType().getAsymmetricPart());
        }

        assertThat(data).containsOnly("rsa.pk.free - RSA - PRIVATE", "secp256r1-key - EC - PUBLIC", "rsa.pk.free - RSA - PUBLIC", "secp256r1-key - EC - PRIVATE");

    }

    @Test
    public void readKeyResource_scenario12() {
        // JKS
        TestConfig.addConfigValue("key.store.type", "JKS");

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "keystore.jks", new TestPasswordLookup("atbash".toCharArray(), "atbash_key".toCharArray()));
        assertThat(keys).hasSize(2);

        boolean privateKey = false;
        boolean publicKey = false;
        for (int i = 0; i < 2; i++) {

            AtbashKey atbashKey = keys.get(i);
            assertThat(atbashKey.getKeyId()).isEqualTo("rsa_jks");  // alias from keystore
            assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPrivateKey.class);
                privateKey = true;
            }
            if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                assertThat(atbashKey.getKey()).isInstanceOf(RSAPublicKey.class);
                publicKey = true;
            }
        }

        assertThat(privateKey).isTrue();
        assertThat(publicKey).isTrue();

    }

    @Test
    public void readKeyResource_scenario13() {
        // unknown key type from path
        Assertions.assertThrows(UnknownKeyResourceTypeException.class, () -> keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "key.txt"));
    }


    @Test
    public void readKeyResource_scenario14() {
        // JWKSet (but same Id)
        Assertions.assertThrows(InvalidJWKSetFormatException.class, () -> keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "duplicate-id.jwkset", new TestPasswordLookup(null, null)));

    }

    @Test
    public void readKeyResource_scenario15() {
        // JWK, RSA public only
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.pub.jwk");
        assertThat(keys).hasSize(1);
    }

    @Test
    public void readKeyResource_scenario16() {
        // JWKSet (RSA Public)

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "test2.jwkset");
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getSecretKeyType().getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);

    }

    @Test
    public void readKeyResource_scenario17() {
        TestConfig.addConfigValue("key.store.type", "JKS");
        // JKS with cert and rsa

        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa_cert.jks", new TestPasswordLookup("password".toCharArray(), null));
        assertThat(keys).hasSize(1);

        boolean privateKey = false;
        boolean publicKey = false;

        AtbashKey atbashKey = keys.get(0);
        assertThat(atbashKey.getKeyId()).isEqualTo("selfsigned");  // alias from keystore
        assertThat(atbashKey.getSecretKeyType().isAsymmetric()).isTrue();
        if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
            assertThat(atbashKey.getKey()).isInstanceOf(RSAPrivateKey.class);
            privateKey = true;
        }
        if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
            assertThat(atbashKey.getKey()).isInstanceOf(RSAPublicKey.class);
            publicKey = true;
        }

        assertThat(privateKey).isFalse();
        assertThat(publicKey).isTrue();

    }

}