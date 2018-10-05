/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPrivate;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import be.atbash.util.exception.AtbashIllegalActionException;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.Test;

import java.nio.charset.Charset;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTParametersBuilderTest {

    @Test
    public void withHeader_default() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(Charset.forName("UTF-8"))))
                .withHeader("UnitTest", "Spock")
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        assertThat(parametersSigning.getHeaderValues()).hasSize(1);
        assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
    }

    @Test
    public void withHeader_multiple() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(Charset.forName("UTF-8"))))
                .withHeader("UnitTest", "Spock")
                .withHeader("key", "value")
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        assertThat(parametersSigning.getHeaderValues()).hasSize(2);
        assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
        assertThat(parametersSigning.getHeaderValues()).containsEntry("key", "value");

    }

    @Test
    public void withHeader_none() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(Charset.forName("UTF-8"))))
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        assertThat(parametersSigning.getHeaderValues()).isEmpty();
    }

    @Test
    public void withHeader_encodingNone() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(Charset.forName("UTF-8"))))
                .withHeader("UnitTest", "Spock")
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersNone.class);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void validate_requiredKeys() {

        JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS).build();
    }

    @Test
    public void JWKKeyType_RSA() {


        AtbashKey rsa = new AtbashKey("somePath", new FakeRSAPrivate());
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(rsa)
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        assertThat(parametersSigning.getKeyType()).isEqualTo(KeyType.RSA);

    }

    @Test
    public void JWKKeyType_hmac() {

        byte[] secret = new byte[16];
        new SecureRandom().nextBytes(secret);

        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("hmacKeyId", "secret".getBytes(Charset.forName("UTF-8")));

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(atbashKey)
                .build();

        assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        assertThat(parametersSigning.getKeyType()).isEqualTo(KeyType.OCT);

    }
}