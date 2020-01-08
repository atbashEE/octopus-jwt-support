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


import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JCAAware;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSProvider;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the default JWS verifier factory.
 */
public class DefaultJWSVerifierFactoryTest {

    @Test
    public void testInterfaces() {

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

        assertThat(factory).isInstanceOf(JWSVerifierFactory.class);
        assertThat(factory).isInstanceOf(JCAAware.class);
        assertThat(factory).isInstanceOf(JWSProvider.class);
    }

    @Test
    public void testAlgSupport() {

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

        assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.HMAC_SHA);
        assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.RSA);
        assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.EC);
        assertThat(factory.supportedJWSAlgorithms()).hasSize(JWSAlgorithm.Family.HMAC_SHA.size()
                + JWSAlgorithm.Family.RSA.size()
                + JWSAlgorithm.Family.EC.size());
    }

    @Test
    public void testDefaultJCAContext() {

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

        assertThat(factory.getJCAContext().getSecureRandom()).isNotNull();
        assertThat(factory.getJCAContext().getProvider()).isNull();
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

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
        factory.getJCAContext().setSecureRandom(secureRandom);

        KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
        SecretKey key = keyGen.generateKey();
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(256);

        JWSVerifier verifier = factory.createJWSVerifier(new JWSHeader(JWSAlgorithm.HS256), key);

        assertThat(verifier.getJCAContext().getSecureRandom().getAlgorithm()).isEqualTo("test");
    }

    @Test
    public void testSetProvider()
            throws Exception {

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
        factory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
        SecretKey key = keyGen.generateKey();
        assertThat(ByteUtils.bitLength(key.getEncoded())).isEqualTo(256);

        JWSVerifier verifier = factory.createJWSVerifier(new JWSHeader(JWSAlgorithm.HS256), key);

        assertThat(verifier.getJCAContext().getProvider().getName()).isEqualTo("BC");
    }
}
