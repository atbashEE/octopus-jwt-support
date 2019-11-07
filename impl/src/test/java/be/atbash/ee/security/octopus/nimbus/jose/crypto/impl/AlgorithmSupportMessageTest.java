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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.Test;

import java.util.Collection;
import java.util.LinkedHashSet;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the algorithm support utility.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-20
 */
public class AlgorithmSupportMessageTest {


    @Test
    public void testWithJWSAlgorithm() {

        JWSAlgorithm unsupported = JWSAlgorithm.ES256;

        Collection<JWSAlgorithm> supported = new LinkedHashSet<>();
        supported.add(JWSAlgorithm.HS256);

        String msg = AlgorithmSupportMessage.unsupportedJWSAlgorithm(unsupported, supported);

        assertThat(msg).isEqualTo("Unsupported JWS algorithm ES256, must be HS256");
    }

    @Test
    public void testWithJWEAlgorithm() {

        JWEAlgorithm unsupported = JWEAlgorithm.A128GCMKW;

        Collection<JWEAlgorithm> supported = new LinkedHashSet<>();
        supported.add(JWEAlgorithm.RSA1_5);
        supported.add(JWEAlgorithm.RSA_OAEP);

        String msg = AlgorithmSupportMessage.unsupportedJWEAlgorithm(unsupported, supported);

        assertThat(msg).isEqualTo("Unsupported JWE algorithm A128GCMKW, must be RSA1_5 or RSA-OAEP");
    }

    @Test
    public void testWithEncryptionMethod() {

        EncryptionMethod unsupported = EncryptionMethod.A128CBC_HS256_DEPRECATED;

        Collection<EncryptionMethod> supported = new LinkedHashSet<>();
        supported.add(EncryptionMethod.A128GCM);
        supported.add(EncryptionMethod.A192GCM);
        supported.add(EncryptionMethod.A256GCM);

        String msg = AlgorithmSupportMessage.unsupportedEncryptionMethod(unsupported, supported);

        assertThat(msg).isEqualTo("Unsupported JWE encryption method A128CBC+HS256, must be A128GCM, A192GCM or A256GCM");
    }

    @Test
    public void testWithEllipticCurve() {

        Curve unsupported = new Curve("P-986");

        Collection<Curve> supported = new LinkedHashSet<>();
        supported.add(Curve.P_256);
        supported.add(Curve.P_384);
        supported.add(Curve.P_521);

        String msg = AlgorithmSupportMessage.unsupportedEllipticCurve(unsupported, supported);

        assertThat(msg).isEqualTo("Unsupported elliptic curve P-986, must be P-256, P-384 or P-521");
    }
}
