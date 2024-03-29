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
 * Tests the EncryptionMethod class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class EncryptionMethodTest {


    @Test
    public void testCMKLengths() {


        Assertions.assertThat(EncryptionMethod.A128CBC_HS256.cekBitLength()).isEqualTo(256);
        Assertions.assertThat(EncryptionMethod.A192CBC_HS384.cekBitLength()).isEqualTo(384);
        Assertions.assertThat(EncryptionMethod.A256CBC_HS512.cekBitLength()).isEqualTo(512);

        Assertions.assertThat(EncryptionMethod.A128GCM.cekBitLength()).isEqualTo(128);
        Assertions.assertThat(EncryptionMethod.A192GCM.cekBitLength()).isEqualTo(192);
        Assertions.assertThat(EncryptionMethod.A256GCM.cekBitLength()).isEqualTo(256);

    }


    @Test
    public void testAESCBCHMACFamily() {

        Assertions.assertThat(EncryptionMethod.Family.AES_CBC_HMAC_SHA).contains(EncryptionMethod.A128CBC_HS256);
        Assertions.assertThat(EncryptionMethod.Family.AES_CBC_HMAC_SHA).contains(EncryptionMethod.A192CBC_HS384);
        Assertions.assertThat(EncryptionMethod.Family.AES_CBC_HMAC_SHA).contains(EncryptionMethod.A256CBC_HS512);
        Assertions.assertThat(EncryptionMethod.Family.AES_CBC_HMAC_SHA.size()).isEqualTo(3);
    }


    @Test
    public void testAESGCMFamily() {

        Assertions.assertThat(EncryptionMethod.Family.AES_GCM).contains(EncryptionMethod.A256GCM);
        Assertions.assertThat(EncryptionMethod.Family.AES_GCM).contains(EncryptionMethod.A192GCM);
        Assertions.assertThat(EncryptionMethod.Family.AES_GCM).contains(EncryptionMethod.A256GCM);

        Assertions.assertThat(EncryptionMethod.Family.AES_GCM.size()).isEqualTo(3);
    }
}
