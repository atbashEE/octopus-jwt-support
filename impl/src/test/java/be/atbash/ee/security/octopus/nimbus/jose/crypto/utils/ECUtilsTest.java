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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.utils;


import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import org.assertj.core.api.Assertions;


public class ECUtilsTest {

    private static ECPrivateKey generateECPrivateKey(Curve curve)
            throws Exception {

        ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();

        return (ECPrivateKey) keyPair.getPrivate();
    }


    private static ECPublicKey generateECPublicKey(Curve curve)
            throws Exception {

        ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(ecParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();

        return (ECPublicKey) keyPair.getPublic();
    }

    @Test
    public void testCurveCheckOk()
            throws Exception {

        ECPublicKey ephemeralPublicKey = generateECPublicKey(Curve.P_256);
        ECPrivateKey privateKey = generateECPrivateKey(Curve.P_256);
        Assertions.assertThat(ECUtils.isPointOnCurve(ephemeralPublicKey, privateKey)).isTrue();
    }
}
