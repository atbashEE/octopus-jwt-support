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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the default JWE decrypter factory.
 */
public class DefaultJWEDecrypterFactoryTest {


    @Test
    public void testInterfaces() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory).isInstanceOf(JWEDecrypterFactory.class);
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

        assertThat(factory.supportedJWEAlgorithms()).hasSize(12);
    }


    @Test
    public void testEncSupport() {

        DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_GCM);
        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_CBC_HMAC_SHA);

        assertThat(factory.supportedEncryptionMethods()).hasSize(6);
    }

}
