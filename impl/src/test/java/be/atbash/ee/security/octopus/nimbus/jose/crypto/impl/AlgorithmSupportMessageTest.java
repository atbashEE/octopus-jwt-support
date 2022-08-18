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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.LinkedHashSet;


/**
 * Tests the algorithm support utility.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class AlgorithmSupportMessageTest {


    @Test
    public void testWithJWSAlgorithm() {

        JWSAlgorithm unsupported = JWSAlgorithm.ES256;

        Collection<JWSAlgorithm> supported = new LinkedHashSet<>();
        supported.add(JWSAlgorithm.HS256);

        String msg = AlgorithmSupportMessage.unsupportedJWSAlgorithm(unsupported, supported);

        Assertions.assertThat(msg).isEqualTo("Unsupported JWS algorithm ES256, must be HS256");
    }

    @Test
    public void testWithEllipticCurve() {

        Curve unsupported = new Curve("P-986");

        Collection<Curve> supported = new LinkedHashSet<>();
        supported.add(Curve.P_256);
        supported.add(Curve.P_384);
        supported.add(Curve.P_521);

        String msg = AlgorithmSupportMessage.unsupportedEllipticCurve(unsupported, supported);

        Assertions.assertThat(msg).isEqualTo("Unsupported elliptic curve P-986, must be P-256, P-384 or P-521");
    }
}
