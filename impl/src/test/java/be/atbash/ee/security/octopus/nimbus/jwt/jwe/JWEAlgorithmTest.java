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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the JWS Algorithm class.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JWEAlgorithmTest {

    @Test
    public void testParse() {

        assertThat(JWEAlgorithm.RSA_OAEP_256).isEqualTo(JWEAlgorithm.parse("RSA-OAEP-256"));

        assertThat(JWEAlgorithm.A128KW).isEqualTo(JWEAlgorithm.parse("A128KW"));
        assertThat(JWEAlgorithm.A192KW).isEqualTo(JWEAlgorithm.parse("A192KW"));
        assertThat(JWEAlgorithm.A256KW).isEqualTo(JWEAlgorithm.parse("A256KW"));

        assertThat(JWEAlgorithm.DIR).isEqualTo(JWEAlgorithm.parse("dir"));

        assertThat(JWEAlgorithm.ECDH_ES).isEqualTo(JWEAlgorithm.parse("ECDH-ES"));

        assertThat(JWEAlgorithm.ECDH_ES_A128KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A128KW"));
        assertThat(JWEAlgorithm.ECDH_ES_A192KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A192KW"));
        assertThat(JWEAlgorithm.ECDH_ES_A256KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A256KW"));

        assertThat(JWEAlgorithm.A128GCMKW).isEqualTo(JWEAlgorithm.parse("A128GCMKW"));
        assertThat(JWEAlgorithm.A192GCMKW).isEqualTo(JWEAlgorithm.parse("A192GCMKW"));
        assertThat(JWEAlgorithm.A256GCMKW).isEqualTo(JWEAlgorithm.parse("A256GCMKW"));

        assertThat(JWEAlgorithm.PBES2_HS256_A128KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS256+A128KW"));
        assertThat(JWEAlgorithm.PBES2_HS384_A192KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS384+A192KW"));
        assertThat(JWEAlgorithm.PBES2_HS512_A256KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS512+A256KW"));
    }


    @Test
    public void testRSAFamily() {

        assertThat(JWEAlgorithm.Family.RSA).contains(JWEAlgorithm.RSA_OAEP_256);
        assertThat(JWEAlgorithm.Family.RSA).hasSize(1);
    }

    @Test
    public void testAxxxKWFamily() {

        assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A128KW);
        assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A192KW);
        assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A256KW);
        assertThat(JWEAlgorithm.Family.AES_KW).hasSize(3);
    }

    @Test
    public void testAxxxGCMKWFamily() {

        assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        assertThat(JWEAlgorithm.Family.AES_GCM_KW).hasSize(3);
    }

    @Test
    public void testECDHFamily() {

        assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES);
        assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A128KW);
        assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A192KW);
        assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A256KW);
        assertThat(JWEAlgorithm.Family.ECDH_ES).hasSize(4);
    }

    /*
    FIXME Not required so no test ?? Family.ASYMMETRIC
	@Test
    public void testAsymmetricSuperFamily() {

        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA1_5));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP_256));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A128KW));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A192KW));
        assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A256KW));
        assertThat(JWEAlgorithm.Family.ASYMMETRIC.size()).isEqualTo(7);
    }



	@Test
    public void testSymmetricSuperFamily() {

        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A128KW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A192KW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256KW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
        assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.DIR));
        assertThat(JWEAlgorithm.Family.ASYMMETRIC.size()).isEqualTo(7);
    }
    */

}
