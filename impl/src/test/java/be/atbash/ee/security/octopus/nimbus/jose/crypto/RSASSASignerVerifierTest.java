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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

// a low level test
class RSASSASignerVerifierTest {

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
    public void happyCase(String alg) throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys("kid");
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        RSASSASigner signer = new RSASSASigner(privateKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(alg)).build();
        Base64URLValue signature = signer.sign(header, "The Secret Message".getBytes());

        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
        boolean verify = verifier.verify(header, "The Secret Message".getBytes(), signature);

        Assertions.assertThat(verify).isTrue();
    }

    @Test
    public void wrongHeaderAlgForVerifier() {
        // This does not happen if you use the higher level classes, only when you instantiate verifiers manually.
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys("kid");
        AtbashKey privateKey = Filters.findPrivateKey(atbashKeys);
        RSASSASigner signer = new RSASSASigner(privateKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse("RS256")).build();
        Base64URLValue signature = signer.sign(header, "The Secret Message".getBytes());

        AtbashKey publicKey = Filters.findPublicKey(atbashKeys);
        RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
        JWSHeader wrongHeader = new JWSHeader.Builder(JWSAlgorithm.parse("ES256")).build();
        Assertions.assertThatThrownBy(() -> verifier.verify(wrongHeader, "The Secret Message".getBytes(), signature)
                ).isInstanceOf(JOSEException.class)
                .hasMessage("Unsupported JWS algorithm ES256, must be RS256, RS384, RS512, PS256, PS384 or PS512");


    }
}