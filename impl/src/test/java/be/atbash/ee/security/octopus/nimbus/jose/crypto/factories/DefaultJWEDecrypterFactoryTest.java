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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JCAAware;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the default JWE decrypter factory.
 */
public class DefaultJWEDecrypterFactoryTest {


    @Test
    public void testInterfaces() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory).isInstanceOf(JWEDecrypterFactory.class);
        assertThat(factory).isInstanceOf(JCAAware.class);
        assertThat(factory).isInstanceOf(JWEProvider.class);
    }


    @Test
    public void testAlgSupport() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.RSA);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.ECDH_ES);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.AES_GCM_KW);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.AES_KW);
        assertThat(factory.supportedJWEAlgorithms()).contains(JWEAlgorithm.DIR);

        assertThat(factory.supportedJWEAlgorithms()).hasSize(14);
    }


    @Test
    public void testEncSupport() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_GCM);
        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_CBC_HMAC_SHA);
        assertThat(factory.supportedEncryptionMethods()).contains(EncryptionMethod.A128CBC_HS256_DEPRECATED);
        assertThat(factory.supportedEncryptionMethods()).contains(EncryptionMethod.A256CBC_HS512_DEPRECATED);

        assertThat(factory.supportedEncryptionMethods()).hasSize(8);
    }

    @Test
    public void testDefaultJCAContext() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory.getJCAContext().getSecureRandom()).isNotNull();
        assertThat(factory.getJCAContext().getProvider()).isNull();
        assertThat(factory.getJCAContext().getKeyEncryptionProvider()).isNull();
        assertThat(factory.getJCAContext().getMACProvider()).isNull();
        assertThat(factory.getJCAContext().getContentEncryptionProvider()).isNull();
    }

    @Test
    public void testSetSecureRandom()
            throws Exception {

        SecureRandom secureRandom = new SecureRandom() {
            @Override
            public String getAlgorithm() {
                return "test";
            }
        };

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
        factory.getJCAContext().setSecureRandom(secureRandom);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // for example
        SecretKey key = keyGen.generateKey();
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);

        JWEDecrypter decrypter = factory.createJWEDecrypter(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), key);

        assertThat(decrypter.getJCAContext().getSecureRandom().getAlgorithm()).isEqualTo("test");
    }

    @Test
    public void testSetProvider()
            throws Exception {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();
        factory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        factory.getJCAContext().setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
        factory.getJCAContext().setMACProvider(BouncyCastleProviderSingleton.getInstance());
        factory.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // for example
        SecretKey key = keyGen.generateKey();
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(128);

        JWEDecrypter decrypter = factory.createJWEDecrypter(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), key);

        assertThat(decrypter.getJCAContext().getProvider().getName()).isEqualTo("BC");
        assertThat(decrypter.getJCAContext().getKeyEncryptionProvider().getName()).isEqualTo("BC");
        assertThat(decrypter.getJCAContext().getMACProvider().getName()).isEqualTo("BC");
        assertThat(decrypter.getJCAContext().getContentEncryptionProvider().getName()).isEqualTo("BC");
    }
}
