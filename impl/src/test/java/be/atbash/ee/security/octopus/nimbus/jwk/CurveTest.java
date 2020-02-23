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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;


public class CurveTest {

    @Test
    public void testStdCurves() {

        assertThat(Curve.P_256.getName()).isEqualTo("P-256");
        assertThat(Curve.P_256.getStdName()).isEqualTo("secp256r1");
        assertThat(Curve.P_256.getOID()).isEqualTo("1.2.840.10045.3.1.7");

        assertThat(Curve.P_256K.getName()).isEqualTo("P-256K");
        assertThat(Curve.P_256K.getStdName()).isEqualTo("secp256k1");
        assertThat(Curve.P_256K.getOID()).isEqualTo("1.3.132.0.10");

        assertThat(Curve.P_384.getName()).isEqualTo("P-384");
        assertThat(Curve.P_384.getStdName()).isEqualTo("secp384r1");
        assertThat(Curve.P_384.getOID()).isEqualTo("1.3.132.0.34");

        assertThat(Curve.P_521.getName()).isEqualTo("P-521");
        assertThat(Curve.P_521.getStdName()).isEqualTo("secp521r1");
        assertThat(Curve.P_521.getOID()).isEqualTo("1.3.132.0.35");

        assertThat(Curve.Ed25519.getName()).isEqualTo("Ed25519");
        assertThat(Curve.Ed25519.getStdName()).isEqualTo("Ed25519");
        assertThat(Curve.Ed25519.getOID()).isNull();

        assertThat(Curve.Ed448.getName()).isEqualTo("Ed448");
        assertThat(Curve.Ed448.getStdName()).isEqualTo("Ed448");
        assertThat(Curve.Ed448.getOID()).isNull();

        assertThat(Curve.X25519.getName()).isEqualTo("X25519");
        assertThat(Curve.X25519.getStdName()).isEqualTo("X25519");
        assertThat(Curve.X25519.getOID()).isNull();

        assertThat(Curve.X448.getName()).isEqualTo("X448");
        assertThat(Curve.X448.getStdName()).isEqualTo("X448");
        assertThat(Curve.X448.getOID()).isNull();
    }

    @Test
    public void testUnsupportedCurveParams() {

        assertThat(new Curve("unsupported").toECParameterSpec()).isNull();
    }

    @Test
    public void testCurveParams() {

        ECParameterSpec ecParameterSpec;

        ecParameterSpec = Curve.P_256.toECParameterSpec();
        assertThat(ecParameterSpec).isNotNull();
        assertThat(Curve.forECParameterSpec(ecParameterSpec)).isEqualTo(Curve.P_256);

        ecParameterSpec = Curve.P_256K.toECParameterSpec();
        assertThat(ecParameterSpec).isNotNull();
        assertThat(Curve.forECParameterSpec(ecParameterSpec)).isEqualTo(Curve.P_256K);

        ecParameterSpec = Curve.P_384.toECParameterSpec();
        assertThat(ecParameterSpec).isNotNull();
        assertThat(Curve.forECParameterSpec(ecParameterSpec)).isEqualTo(Curve.P_384);

        ecParameterSpec = Curve.P_521.toECParameterSpec();
        assertThat(ecParameterSpec).isNotNull();
        assertThat(Curve.forECParameterSpec(ecParameterSpec)).isEqualTo(Curve.P_521);

        // No support
        assertThat(Curve.Ed25519.toECParameterSpec()).isNull();
        assertThat(Curve.Ed448.toECParameterSpec()).isNull();
        assertThat(Curve.X25519.toECParameterSpec()).isNull();
        assertThat(Curve.X448.toECParameterSpec()).isNull();
    }

    @Test
    public void testCurveForStdName() {

        assertThat(Curve.parse("secp256r1")).isEqualTo(Curve.P_256);
        assertThat(Curve.parse("prime256v1")).isEqualTo(Curve.P_256);

        assertThat(Curve.parse("secp256k1")).isEqualTo(Curve.P_256K);

        assertThat(Curve.parse("secp384r1")).isEqualTo(Curve.P_384);

        assertThat(Curve.parse("secp521r1")).isEqualTo(Curve.P_521);

        assertThat(Curve.parse("Ed25519")).isEqualTo(Curve.Ed25519);

        assertThat(Curve.parse("Ed448")).isEqualTo(Curve.Ed448);

        assertThat(Curve.parse("X25519")).isEqualTo(Curve.X25519);

        assertThat(Curve.parse("X448")).isEqualTo(Curve.X448);
    }

    @Test
    public void testCurveForOID() {

        assertThat(Curve.forOID(Curve.P_256.getOID())).isEqualTo(Curve.P_256);
        assertThat(Curve.forOID(Curve.P_256K.getOID())).isEqualTo(Curve.P_256K);
        assertThat(Curve.forOID(Curve.P_384.getOID())).isEqualTo(Curve.P_384);
        assertThat(Curve.forOID(Curve.P_521.getOID())).isEqualTo(Curve.P_521);
    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/197/jwsalgorithm-should-have-knowledge-of-its
    public void testCurveForJWSAlgorithm() {

        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.ES256)).isEqualTo(Collections.singleton(Curve.P_256));
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.ES256K)).isEqualTo(Collections.singleton(Curve.P_256K));
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.ES384)).isEqualTo(Collections.singleton(Curve.P_384));
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.ES512)).isEqualTo(Collections.singleton(Curve.P_521));
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.EdDSA)).isEqualTo(new HashSet<>(Arrays.asList(Curve.Ed25519, Curve.Ed448)));

        // Not EC based
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.RS256)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.RS384)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.RS512)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.PS256)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.PS384)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.PS512)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.HS256)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.HS384)).isEmpty();
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.HS512)).isEmpty();

        // Unsupported
        assertThat(Curve.forJWSAlgorithm(JWSAlgorithm.parse("unsupported-jws-alg"))).isEmpty();

        // null
        assertThat(Curve.forJWSAlgorithm(null)).isEmpty();
    }
}
