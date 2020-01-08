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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.fake.FakeECPrivate;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPublic;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTParametersSigningTest {


    @Test
    public void getKeyID_hmac() {

        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("hmacKeyId", "secret".getBytes(StandardCharsets.UTF_8));

        JWTParametersSigning parameters = new JWTParametersSigning(null, atbashKey);

        assertThat(parameters.getKeyID()).isEqualTo("hmacKeyId");
    }

    @Test
    public void getKeyID_rsa() {

        AtbashKey key = new AtbashKey("rsaKeyId", new FakeRSAPublic());
        JWTParametersSigning parameters = new JWTParametersSigning(null, key);

        assertThat(parameters.getKeyID()).isEqualTo("rsaKeyId");
    }

    @Test
    public void getKeyID_ec() {
        AtbashKey key = new AtbashKey("ecKeyId", new FakeECPrivate());
        JWTParametersSigning parameters = new JWTParametersSigning(null, key);

        assertThat(parameters.getKeyID()).isEqualTo("ecKeyId");
    }

}
