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


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.*;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the default JWE decrypter factory.
 */
public class DefaultJWEDecrypterFactoryTest {

    private static final String KID = "kidValue";

    private DefaultJWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

    @Test
    public void testInterfaces() {

        assertThat(factory).isInstanceOf(JWEDecrypterFactory.class);
        assertThat(factory).isInstanceOf(JWEProvider.class);
    }


    @Test
    public void testAlgSupport() {

        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.RSA);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.ECDH_ES);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.AES_GCM_KW);
        assertThat(factory.supportedJWEAlgorithms()).containsAll(JWEAlgorithm.Family.AES_KW);
        assertThat(factory.supportedJWEAlgorithms()).contains(JWEAlgorithm.DIR);

        assertThat(factory.supportedJWEAlgorithms()).hasSize(12);
    }


    @Test
    public void testEncSupport() {

        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_GCM);
        assertThat(factory.supportedEncryptionMethods()).containsAll(EncryptionMethod.Family.AES_CBC_HMAC_SHA);

        assertThat(factory.supportedEncryptionMethods()).hasSize(6);
    }

    @Test
    public void createJWEDecryptor_RSA() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : RSADecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : RSADecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                JWEDecrypter decrypter = factory.createJWEDecrypter(header, privateKeys.get(0).getKey());

                assertThat(decrypter).isNotNull();
                assertThat(decrypter).isInstanceOf(RSADecrypter.class);
            }
        }
    }

    @Test
    public void createJWEDecryptor_wrongKeyForHeader_1Bis() {
        //Public Key instead of PrivateKey
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : RSADecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : RSADecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, privateKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface java.security.interfaces.RSAPrivateKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_wrongKeyForHeader_1() {
        // EC key instead of RSA key
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : RSADecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : RSADecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, privateKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface java.security.interfaces.RSAPrivateKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_EC() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : ECDHDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                JWEDecrypter decrypter = factory.createJWEDecrypter(header, privateKeys.get(0).getKey());

                assertThat(decrypter).isNotNull();
                assertThat(decrypter).isInstanceOf(ECDHDecrypter.class);
            }
        }
    }

    @Test
    public void createJWEDecryptor_wrongKeyForHeader_2() {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : ECDHDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, privateKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface java.security.interfaces.ECPrivateKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_wrongKeyForHeader_2Bis() {
        List<AtbashKey> atbashKeys = TestKeys.generateECKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : ECDHDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, privateKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface java.security.interfaces.ECPrivateKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_OCT() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateOCTKeys(KID);

        JWEAlgorithm supportedAlgorithm = JWEAlgorithm.A256KW; // Algorithm depends on key length. This is one of the 2

        for (EncryptionMethod supportedEncryptionMethod : AESDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

            JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
            JWEDecrypter decrypter = factory.createJWEDecrypter(header, atbashKeys.get(0).getKey());

            assertThat(decrypter).isNotNull();
            assertThat(decrypter).isInstanceOf(AESDecrypter.class);
        }

    }

    @Test
    public void createJWEDecryptor_OCT_WrongKeyLength() {
        List<AtbashKey> atbashKeys = TestKeys.generateOCTKeys(KID);

        JWEAlgorithm supportedAlgorithm = JWEAlgorithm.A128KW; // Algorithm depends on key length. This is a wrong one.

        for (EncryptionMethod supportedEncryptionMethod : AESDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

            JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
            KeyLengthException exception = Assertions.assertThrows(KeyLengthException.class, () -> factory.createJWEDecrypter(header, atbashKeys.get(0).getKey()));

            assertThat(exception.getMessage()).isEqualTo("Unexpected key length (for A128KW algorithm)");
        }

    }

    @Test
    public void createJWEDecryptor_OCT_WrongType() {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);
        List<AtbashKey> privateKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(atbashKeys);
        for (JWEAlgorithm supportedAlgorithm : AESDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : AESDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, privateKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface javax.crypto.SecretKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_DIR() throws JOSEException {

        for (JWEAlgorithm supportedAlgorithm : DirectDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                // Length of key is dependent on the encryption method
                List<AtbashKey> atbashKeys = TestKeys.generateOCTKeys(KID, supportedEncryptionMethod.cekBitLength());

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                JWEDecrypter decrypter = factory.createJWEDecrypter(header, atbashKeys.get(0).getKey());

                assertThat(decrypter).isNotNull();
                assertThat(decrypter).isInstanceOf(DirectDecrypter.class);
            }
        }
    }

    @Test
    public void createJWEDecryptor_DIR_WrongKeyForHeader()  {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);

        for (JWEAlgorithm supportedAlgorithm : DirectDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, atbashKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface javax.crypto.SecretKey");
            }
        }
    }

    @Test
    public void createJWEDecryptor_PW() throws JOSEException {
        List<AtbashKey> atbashKeys = TestKeys.generateOCTKeys(KID);

        for (JWEAlgorithm supportedAlgorithm : PasswordBasedDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                JWEDecrypter decrypter = factory.createJWEDecrypter(header, atbashKeys.get(0).getKey());

                assertThat(decrypter).isNotNull();
                assertThat(decrypter).isInstanceOf(PasswordBasedDecrypter.class);
            }
        }
    }

    @Test
    public void createJWEDecryptor_PW_WrongKeyForHeader()  {
        List<AtbashKey> atbashKeys = TestKeys.generateRSAKeys(KID);

        for (JWEAlgorithm supportedAlgorithm : PasswordBasedDecrypter.SUPPORTED_ALGORITHMS) {

            for (EncryptionMethod supportedEncryptionMethod : PasswordBasedDecrypter.SUPPORTED_ENCRYPTION_METHODS) {

                JWEHeader header = new JWEHeader.Builder(supportedAlgorithm, supportedEncryptionMethod).build();
                KeyTypeException exception = Assertions.assertThrows(KeyTypeException.class, () -> factory.createJWEDecrypter(header, atbashKeys.get(0).getKey()));

                assertThat(exception.getMessage()).isEqualTo("Invalid key: Must be an instance of interface javax.crypto.SecretKey");
            }
        }
    }
}
