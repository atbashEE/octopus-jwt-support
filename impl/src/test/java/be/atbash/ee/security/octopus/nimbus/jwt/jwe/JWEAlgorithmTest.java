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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests the JWS Algorithm class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWEAlgorithmTest {

    @Test
    public void testParse() {

        Assertions.assertThat(JWEAlgorithm.RSA_OAEP_256).isEqualTo(JWEAlgorithm.parse("RSA-OAEP-256"));
        Assertions.assertThat(JWEAlgorithm.RSA_OAEP_512).isEqualTo(JWEAlgorithm.parse("RSA-OAEP-512"));

        Assertions.assertThat(JWEAlgorithm.A128KW).isEqualTo(JWEAlgorithm.parse("A128KW"));
        Assertions.assertThat(JWEAlgorithm.A192KW).isEqualTo(JWEAlgorithm.parse("A192KW"));
        Assertions.assertThat(JWEAlgorithm.A256KW).isEqualTo(JWEAlgorithm.parse("A256KW"));

        Assertions.assertThat(JWEAlgorithm.DIR).isEqualTo(JWEAlgorithm.parse("dir"));

        Assertions.assertThat(JWEAlgorithm.ECDH_ES).isEqualTo(JWEAlgorithm.parse("ECDH-ES"));

        Assertions.assertThat(JWEAlgorithm.ECDH_ES_A128KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A128KW"));
        Assertions.assertThat(JWEAlgorithm.ECDH_ES_A192KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A192KW"));
        Assertions.assertThat(JWEAlgorithm.ECDH_ES_A256KW).isEqualTo(JWEAlgorithm.parse("ECDH-ES+A256KW"));

        Assertions.assertThat(JWEAlgorithm.A128GCMKW).isEqualTo(JWEAlgorithm.parse("A128GCMKW"));
        Assertions.assertThat(JWEAlgorithm.A192GCMKW).isEqualTo(JWEAlgorithm.parse("A192GCMKW"));
        Assertions.assertThat(JWEAlgorithm.A256GCMKW).isEqualTo(JWEAlgorithm.parse("A256GCMKW"));

        Assertions.assertThat(JWEAlgorithm.PBES2_HS256_A128KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS256+A128KW"));
        Assertions.assertThat(JWEAlgorithm.PBES2_HS384_A192KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS384+A192KW"));
        Assertions.assertThat(JWEAlgorithm.PBES2_HS512_A256KW).isEqualTo(JWEAlgorithm.parse("PBES2-HS512+A256KW"));
    }


    @Test
    public void testRSAFamily() {

        Assertions.assertThat(JWEAlgorithm.Family.RSA).containsOnly(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP_384, JWEAlgorithm.RSA_OAEP_512);
        Assertions.assertThat(JWEAlgorithm.Family.RSA).hasSize(3);
    }

    @Test
    public void testAxxxKWFamily() {

        Assertions.assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A128KW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A192KW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_KW).contains(JWEAlgorithm.A256KW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_KW).hasSize(3);
    }

    @Test
    public void testAxxxGCMKWFamily() {

        Assertions.assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_GCM_KW).contains(JWEAlgorithm.A256GCMKW);
        Assertions.assertThat(JWEAlgorithm.Family.AES_GCM_KW).hasSize(3);
    }

    @Test
    public void testECDHFamily() {

        Assertions.assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES);
        Assertions.assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A128KW);
        Assertions.assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A192KW);
        Assertions.assertThat(JWEAlgorithm.Family.ECDH_ES).contains(JWEAlgorithm.ECDH_ES_A256KW);
        Assertions.assertThat(JWEAlgorithm.Family.ECDH_ES).hasSize(4);
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
        Assertions.assertThat(JWEAlgorithm.Family.ASYMMETRIC.size()).isEqualTo(7);
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
        Assertions.assertThat(JWEAlgorithm.Family.ASYMMETRIC.size()).isEqualTo(7);
    }
    */

}
