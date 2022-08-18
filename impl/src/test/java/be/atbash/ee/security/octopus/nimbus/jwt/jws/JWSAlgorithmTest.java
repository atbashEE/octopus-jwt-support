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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;


/**
 * Tests the JWS Algorithm class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWSAlgorithmTest {

    @Test
    public void testParse() {

        Assertions.assertThat(JWSAlgorithm.parse("HS256")).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(JWSAlgorithm.parse("HS384")).isEqualTo(JWSAlgorithm.HS384);
        Assertions.assertThat(JWSAlgorithm.parse("HS512")).isEqualTo(JWSAlgorithm.HS512);

        Assertions.assertThat(JWSAlgorithm.parse("RS256")).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(JWSAlgorithm.parse("RS384")).isEqualTo(JWSAlgorithm.RS384);
        Assertions.assertThat(JWSAlgorithm.parse("RS512")).isEqualTo(JWSAlgorithm.RS512);

        Assertions.assertThat(JWSAlgorithm.parse("ES256")).isEqualTo(JWSAlgorithm.ES256);
        Assertions.assertThat(JWSAlgorithm.parse("ES256K")).isEqualTo(JWSAlgorithm.ES256K);
        Assertions.assertThat(JWSAlgorithm.parse("ES384")).isEqualTo(JWSAlgorithm.ES384);
        Assertions.assertThat(JWSAlgorithm.parse("ES512")).isEqualTo(JWSAlgorithm.ES512);

        Assertions.assertThat(JWSAlgorithm.parse("PS256")).isEqualTo(JWSAlgorithm.PS256);
        Assertions.assertThat(JWSAlgorithm.parse("PS384")).isEqualTo(JWSAlgorithm.PS384);
        Assertions.assertThat(JWSAlgorithm.parse("PS512")).isEqualTo(JWSAlgorithm.PS512);

        Assertions.assertThat(JWSAlgorithm.parse("EdDSA")).isEqualTo(JWSAlgorithm.EdDSA);
    }

    @Test
    public void testHMACFamily() {

        Assertions.assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS256)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS384)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS512)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.HMAC_SHA.size()).isEqualTo(3);
    }

    @Test
    public void testRSAFamily() {

        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS256)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS384)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS512)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS256)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS384)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS512)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.RSA.size()).isEqualTo(6);
    }

    @Test
    public void testECFamily() {

        Assertions.assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES256)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES256K)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES384)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES512)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.EC.size()).isEqualTo(4);
    }

    @Test
    public void testEDFamily() {

        Assertions.assertThat(JWSAlgorithm.Family.ED.contains(JWSAlgorithm.EdDSA)).isTrue();
        Assertions.assertThat(JWSAlgorithm.Family.ED.size()).isEqualTo(1);
    }
	

	/*
	public void testSignatureSuperFamily() {
		
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.RS512));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.PS512));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES256));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES256K));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES384));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.ES512));
		assertTrue(JWSAlgorithm.Family.SIGNATURE.contains(JWSAlgorithm.EdDSA));
		Assertions.assertThat(JWSAlgorithm.Family.SIGNATURE.size()).isEqualTo(11);
	}

	 */
}
