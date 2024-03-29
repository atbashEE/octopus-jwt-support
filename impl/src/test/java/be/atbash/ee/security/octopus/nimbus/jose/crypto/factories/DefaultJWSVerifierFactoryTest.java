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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.factories;


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.Ed25519Verifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSProvider;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.List;


/**
 * Tests the default JWS verifier factory.
 */
public class DefaultJWSVerifierFactoryTest {

    private final DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();

    private static final String KID = "kidValue";

    @AfterEach
    public void cleanup() {
        MDC.clear();
    }

    @Test
    void testInterfaces() {

        Assertions.assertThat(factory).isInstanceOf(JWSVerifierFactory.class);
        Assertions.assertThat(factory).isInstanceOf(JWSProvider.class);
    }

    @Test
    void testAlgSupport() {

        Assertions.assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.HMAC_SHA);
        Assertions.assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.RSA);
        Assertions.assertThat(factory.supportedJWSAlgorithms()).containsAll(JWSAlgorithm.Family.EC);
        Assertions.assertThat(factory.supportedJWSAlgorithms()).hasSize(JWSAlgorithm.Family.HMAC_SHA.size()
                + JWSAlgorithm.Family.RSA.size()
                + JWSAlgorithm.Family.EC.size());
    }

    @Test
    void createJWSVerifier_rsa() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : RSASSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            JWSVerifier verifier = factory.createJWSVerifier(header, publicKeys.get(0).getKey());
            Assertions.assertThat(verifier).isNotNull();
            Assertions.assertThat(verifier).isInstanceOf(RSASSAVerifier.class);

            Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();
        }
    }

    @Test
    void createJWSVerifier_rsa_wrongKeyForHeader_1Bis() {
        //Private Key instead of Public
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : RSASSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of interface java.security.interfaces.RSAPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey' do no match");

            // Since we are using a for loop we need to clear the MDC.
            MDC.clear();
        }
    }

    @Test
    void createJWSVerifier_rsa_wrongKeyForHeader_1() {
        //EC Key instead of RSA
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : RSASSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of interface java.security.interfaces.RSAPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey' do no match");
        }
    }

    @Test
    void createJWSVerifier_ec() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : ECDSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            JWSVerifier verifier = factory.createJWSVerifier(header, publicKeys.get(0).getKey());
            Assertions.assertThat(verifier).isNotNull();
            Assertions.assertThat(verifier).isInstanceOf(ECDSAVerifier.class);

            Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();
        }
    }

    @Test
    void createJWSVerifier_ec_wrongKeyForHeader_1Bis() {
        //Private Key instead of Public
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : ECDSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of interface java.security.interfaces.ECPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey' do no match");
        }
    }

    @Test
    void createJWSVerifier_ec_wrongKeyForHeader_1() {
        //RSA Key instead of RSA
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : ECDSAVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of interface java.security.interfaces.ECPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey' do no match");
        }
    }

    @Test
    void createJWSVerifier_OCT() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateOCTKeys(KID);

        for (JWSAlgorithm supportedAlgorithm : MACVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            JWSVerifier verifier = factory.createJWSVerifier(header, atbashKeys.get(0).getKey());
            Assertions.assertThat(verifier).isNotNull();
            Assertions.assertThat(verifier).isInstanceOf(MACVerifier.class);

            Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();
        }
    }

    @Test
    void createJWSVerifier_OCT_wrongKeyForHeader() {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);

        for (JWSAlgorithm supportedAlgorithm : MACVerifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, atbashKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of interface javax.crypto.SecretKey");
            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey' do no match");
        }
    }

    @Test
    void createJWSVerifier_OKP() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateOKPKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : Ed25519Verifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            JWSVerifier verifier = factory.createJWSVerifier(header, publicKeys.get(0).getKey());
            Assertions.assertThat(verifier).isNotNull();
            Assertions.assertThat(verifier).isInstanceOf(Ed25519Verifier.class);

            Assertions.assertThat(MDC.getCopyOfContextMap()).isEmpty();

        }
    }

    @Test
    void createJWSVerifier_OKP_wrongKeyForHeader_3() {
        List<AtbashKey> atbashKeys = TestKeys.generateOKPKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : Ed25519Verifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, privateKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of class org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey' do no match");

        }
    }

    @Test
    void createJWSVerifier_OKP_wrongKeyForHeader_3bis() {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWSAlgorithm supportedAlgorithm : Ed25519Verifier.SUPPORTED_ALGORITHMS) {

            JWSHeader header = new JWSHeader.Builder(supportedAlgorithm).build();

            Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                    .isInstanceOf(KeyTypeException.class)
                    .hasMessage("Invalid key: Must be an instance of class org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey");

            Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("The header algorithm '" + supportedAlgorithm.getName() + "' and the Key type 'org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey' do no match");
        }
    }

    @Test
    void createJWSVerifier_UnknownAlg() {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);


        JWSHeader header = new JWSHeader.Builder(new JWSAlgorithm("JUnit")).build();

        Assertions.assertThatThrownBy(() -> factory.createJWSVerifier(header, publicKeys.get(0).getKey()))
                .isInstanceOf(JOSEException.class)
                .hasMessage("Unsupported JWS algorithm: JUnit");

        Assertions.assertThat(MDC.get(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON)).isEqualTo("No Signature verifier found for the algorithm specified in Header JUnit.");

    }

}
