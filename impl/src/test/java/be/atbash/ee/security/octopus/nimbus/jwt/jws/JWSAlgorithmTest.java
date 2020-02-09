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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWS Algorithm class.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JWSAlgorithmTest {

    @Test
    public void testParse() {

        assertThat(JWSAlgorithm.parse("HS256")).isEqualTo(JWSAlgorithm.HS256);
        assertThat(JWSAlgorithm.parse("HS384")).isEqualTo(JWSAlgorithm.HS384);
        assertThat(JWSAlgorithm.parse("HS512")).isEqualTo(JWSAlgorithm.HS512);

        assertThat(JWSAlgorithm.parse("RS256")).isEqualTo(JWSAlgorithm.RS256);
        assertThat(JWSAlgorithm.parse("RS384")).isEqualTo(JWSAlgorithm.RS384);
        assertThat(JWSAlgorithm.parse("RS512")).isEqualTo(JWSAlgorithm.RS512);

        assertThat(JWSAlgorithm.parse("ES256")).isEqualTo(JWSAlgorithm.ES256);
        assertThat(JWSAlgorithm.parse("ES256K")).isEqualTo(JWSAlgorithm.ES256K);
        assertThat(JWSAlgorithm.parse("ES384")).isEqualTo(JWSAlgorithm.ES384);
        assertThat(JWSAlgorithm.parse("ES512")).isEqualTo(JWSAlgorithm.ES512);

        assertThat(JWSAlgorithm.parse("PS256")).isEqualTo(JWSAlgorithm.PS256);
        assertThat(JWSAlgorithm.parse("PS384")).isEqualTo(JWSAlgorithm.PS384);
        assertThat(JWSAlgorithm.parse("PS512")).isEqualTo(JWSAlgorithm.PS512);

        assertThat(JWSAlgorithm.parse("EdDSA")).isEqualTo(JWSAlgorithm.EdDSA);
    }

    @Test
    public void testHMACFamily() {

        assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS256)).isTrue();
        assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS384)).isTrue();
        assertThat(JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.HS512)).isTrue();
        assertThat(JWSAlgorithm.Family.HMAC_SHA.size()).isEqualTo(3);
    }

    @Test
    public void testRSAFamily() {

        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS256)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS384)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.RS512)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS256)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS384)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.PS512)).isTrue();
        assertThat(JWSAlgorithm.Family.RSA.size()).isEqualTo(6);
    }

    @Test
    public void testECFamily() {

        assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES256)).isTrue();
        assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES256K)).isTrue();
        assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES384)).isTrue();
        assertThat(JWSAlgorithm.Family.EC.contains(JWSAlgorithm.ES512)).isTrue();
        assertThat(JWSAlgorithm.Family.EC.size()).isEqualTo(4);
    }

    @Test
    public void testEDFamily() {

        assertThat(JWSAlgorithm.Family.ED.contains(JWSAlgorithm.EdDSA)).isTrue();
        assertThat(JWSAlgorithm.Family.ED.size()).isEqualTo(1);
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
		assertThat(JWSAlgorithm.Family.SIGNATURE.size()).isEqualTo(11);
	}

	 */
}
