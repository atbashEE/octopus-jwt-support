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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

// A low level test case
class ECDSASignerVerifierTest {

    @BeforeEach
    public void cleanup() {
        MDC.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {"256", "384", "521"})
    void happyCase(String data) throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys("kid", "P-" + data);
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey.getKey());
        JWSHeader header = new JWSHeader.Builder(defineAlgorithm(data)).build();
        Base64URLValue signature = signer.sign(header, "The Secret Message".getBytes());

        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey.getKey());
        boolean verify = verifier.verify(header, "The Secret Message".getBytes(), signature);

        Assertions.assertThat(verify).isTrue();
        Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();
    }

    private JWSAlgorithm defineAlgorithm(String data) {
        switch (data) {
            case "256" : return JWSAlgorithm.ES256;
            case "384" : return JWSAlgorithm.ES384;
            case "521" : return JWSAlgorithm.ES512;

            default:
                throw new IllegalStateException("Unexpected value: " + data);
        }
    }

    @Test
    void invalidSignature() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys("kid", "P-256" );
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey.getKey());
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        Base64URLValue signature = signer.sign(header, "The Secret Message".getBytes());

        // Create a second key pai so that verification fails
        atbashKeys = TestKeys.generateECKeys("kid", "P-256");
        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey.getKey());
        boolean verify = verifier.verify(header, "The Secret Message".getBytes(), signature);

        Assertions.assertThat(verify).isFalse();
        Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();

    }

}