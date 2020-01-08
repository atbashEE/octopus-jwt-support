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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the AES KeyWrap static methods.
 */
public class AESKWTest {


    @Test
    // From http://tools.ietf.org/html/rfc7517#appendix-C
    public void testVectorEncryptCEK()
            throws Exception {

         byte[] cek = {
                (byte) 111, (byte) 27, (byte) 25, (byte) 52, (byte) 66, (byte) 29, (byte) 20, (byte) 78,
                (byte) 92, (byte) 176, (byte) 56, (byte) 240, (byte) 65, (byte) 208, (byte) 82, (byte) 112,
                (byte) 161, (byte) 131, (byte) 36, (byte) 55, (byte) 202, (byte) 236, (byte) 185, (byte) 172,
                (byte) 129, (byte) 23, (byte) 153, (byte) 194, (byte) 195, (byte) 48, (byte) 253, (byte) 182};

         byte[] kek = {
                (byte) 110, (byte) 171, (byte) 169, (byte) 92, (byte) 129, (byte) 92, (byte) 109, (byte) 117,
                (byte) 233, (byte) 242, (byte) 116, (byte) 233, (byte) 170, (byte) 14, (byte) 24, (byte) 75};

         byte[] encryptedCEK = AESKW.wrapCEK(new SecretKeySpec(cek, "AES"), new SecretKeySpec(kek, "AES"), null);

         byte[] expectedEncryptedCEK = {
                (byte) 78, (byte) 186, (byte) 151, (byte) 59, (byte) 11, (byte) 141, (byte) 81, (byte) 240,
                (byte) 213, (byte) 245, (byte) 83, (byte) 211, (byte) 53, (byte) 188, (byte) 134, (byte) 188,
                (byte) 66, (byte) 125, (byte) 36, (byte) 200, (byte) 222, (byte) 124, (byte) 5, (byte) 103,
                (byte) 249, (byte) 52, (byte) 117, (byte) 184, (byte) 140, (byte) 81, (byte) 246, (byte) 158,
                (byte) 161, (byte) 177, (byte) 20, (byte) 33, (byte) 245, (byte) 57, (byte) 59, (byte) 4};

        assertThat(Arrays.equals(expectedEncryptedCEK, encryptedCEK)).isTrue();
    }


    @Test
    public void testVectorDecryptCEK()
            throws Exception {

         byte[] encryptedCEK = {
                (byte) 78, (byte) 186, (byte) 151, (byte) 59, (byte) 11, (byte) 141, (byte) 81, (byte) 240,
                (byte) 213, (byte) 245, (byte) 83, (byte) 211, (byte) 53, (byte) 188, (byte) 134, (byte) 188,
                (byte) 66, (byte) 125, (byte) 36, (byte) 200, (byte) 222, (byte) 124, (byte) 5, (byte) 103,
                (byte) 249, (byte) 52, (byte) 117, (byte) 184, (byte) 140, (byte) 81, (byte) 246, (byte) 158,
                (byte) 161, (byte) 177, (byte) 20, (byte) 33, (byte) 245, (byte) 57, (byte) 59, (byte) 4};

         byte[] kek = {
                (byte) 110, (byte) 171, (byte) 169, (byte) 92, (byte) 129, (byte) 92, (byte) 109, (byte) 117,
                (byte) 233, (byte) 242, (byte) 116, (byte) 233, (byte) 170, (byte) 14, (byte) 24, (byte) 75};

         SecretKey cek = AESKW.unwrapCEK(new SecretKeySpec(kek, "AES"), encryptedCEK, null);

         byte[] expectedCEK = {
                (byte) 111, (byte) 27, (byte) 25, (byte) 52, (byte) 66, (byte) 29, (byte) 20, (byte) 78,
                (byte) 92, (byte) 176, (byte) 56, (byte) 240, (byte) 65, (byte) 208, (byte) 82, (byte) 112,
                (byte) 161, (byte) 131, (byte) 36, (byte) 55, (byte) 202, (byte) 236, (byte) 185, (byte) 172,
                (byte) 129, (byte) 23, (byte) 153, (byte) 194, (byte) 195, (byte) 48, (byte) 253, (byte) 182};

        assertThat(Arrays.equals(expectedCEK, cek.getEncoded())).isTrue();
        assertThat(cek.getAlgorithm()).isEqualTo("AES");
    }

    @Test
    public void testUnwrapCEK_adjustKEKAlg()
            throws Exception {

         byte[] encryptedCEK = {
                (byte) 78, (byte) 186, (byte) 151, (byte) 59, (byte) 11, (byte) 141, (byte) 81, (byte) 240,
                (byte) 213, (byte) 245, (byte) 83, (byte) 211, (byte) 53, (byte) 188, (byte) 134, (byte) 188,
                (byte) 66, (byte) 125, (byte) 36, (byte) 200, (byte) 222, (byte) 124, (byte) 5, (byte) 103,
                (byte) 249, (byte) 52, (byte) 117, (byte) 184, (byte) 140, (byte) 81, (byte) 246, (byte) 158,
                (byte) 161, (byte) 177, (byte) 20, (byte) 33, (byte) 245, (byte) 57, (byte) 59, (byte) 4};

         byte[] kek = {
                (byte) 110, (byte) 171, (byte) 169, (byte) 92, (byte) 129, (byte) 92, (byte) 109, (byte) 117,
                (byte) 233, (byte) 242, (byte) 116, (byte) 233, (byte) 170, (byte) 14, (byte) 24, (byte) 75};

         SecretKey cek = AESKW.unwrapCEK(new SecretKeySpec(kek, "SOME_ALG_NOT_AES"), encryptedCEK, null);

         byte[] expectedCEK = {
                (byte) 111, (byte) 27, (byte) 25, (byte) 52, (byte) 66, (byte) 29, (byte) 20, (byte) 78,
                (byte) 92, (byte) 176, (byte) 56, (byte) 240, (byte) 65, (byte) 208, (byte) 82, (byte) 112,
                (byte) 161, (byte) 131, (byte) 36, (byte) 55, (byte) 202, (byte) 236, (byte) 185, (byte) 172,
                (byte) 129, (byte) 23, (byte) 153, (byte) 194, (byte) 195, (byte) 48, (byte) 253, (byte) 182};

        assertThat(cek.getEncoded()).isEqualTo(expectedCEK);
        assertThat(cek.getAlgorithm()).isEqualTo("AES");
    }
}
