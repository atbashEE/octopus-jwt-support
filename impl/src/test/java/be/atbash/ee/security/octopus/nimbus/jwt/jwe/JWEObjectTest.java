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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JWEJCAContext;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JWE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2014-08-20
 */
public class JWEObjectTest {

    @Test
    public void testBase64URLConstructor()
            throws Exception {

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5,
                EncryptionMethod.A128CBC_HS256);

        Base64URLValue firstPart = header.toBase64URL();
        Base64URLValue secondPart = new Base64URLValue("abc");
        Base64URLValue thirdPart = new Base64URLValue("def");
        Base64URLValue fourthPart = new Base64URLValue("ghi");
        Base64URLValue fifthPart = new Base64URLValue("jkl");

        JWEObject jwe = new JWEObject(firstPart, secondPart,
                thirdPart, fourthPart,
                fifthPart);

        assertThat(jwe.getHeader().toBase64URL()).isEqualTo(firstPart);
        assertThat(jwe.getEncryptedKey()).isEqualTo(secondPart);
        assertThat(jwe.getIV()).isEqualTo(thirdPart);
        assertThat(jwe.getCipherText()).isEqualTo(fourthPart);

        assertThat(jwe.serialize()).isEqualTo(firstPart.toString() + ".abc.def.ghi.jkl");
        assertThat(jwe.getParsedString()).isEqualTo(firstPart.toString() + ".abc.def.ghi.jkl");

        assertThat(jwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testRejectUnsupportedJWEAlgorithmOnEncrypt() {

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
        JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

        try {
            jwe.encrypt(new JWEEncrypter() {
                @Override
                public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
                    return null;
                }

                @Override
                public Set<JWEAlgorithm> supportedJWEAlgorithms() {
                    return Collections.singleton(new JWEAlgorithm("xyz"));
                }

                @Override
                public Set<EncryptionMethod> supportedEncryptionMethods() {
                    return null;
                }

                @Override
                public JWEJCAContext getJCAContext() {
                    return null;
                }
            });
        } catch (JOSEException e) {
            assertThat(e.getMessage()).isEqualTo("The \"RSA1_5\" algorithm is not supported by the JWE encrypter: Supported algorithms: [xyz]");
        }
    }

    @Test
    public void testRejectUnsupportedJWEMethodOnEncrypt() {

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
        JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

        try {
            jwe.encrypt(new JWEEncrypter() {
                @Override
                public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
                    return null;
                }

                @Override
                public Set<JWEAlgorithm> supportedJWEAlgorithms() {
                    return Collections.singleton(JWEAlgorithm.RSA1_5);
                }

                @Override
                public Set<EncryptionMethod> supportedEncryptionMethods() {
                    return Collections.singleton(new EncryptionMethod("xyz"));
                }

                @Override
                public JWEJCAContext getJCAContext() {
                    return null;
                }
            });
        } catch (JOSEException e) {
            assertThat(e.getMessage()).isEqualTo("The \"A128CBC-HS256\" encryption method or key size is not supported by the JWE encrypter: Supported methods: [xyz]");
        }
    }
}
