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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.fake.FakeECPublic;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPrivate;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class JWTParametersBuilderTest {

    @Test
    public void withHeader_default() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .withHeader("UnitTest", "Spock")
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        Assertions.assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        Assertions.assertThat(parametersSigning.getHeaderValues()).hasSize(1);
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
    }

    @Test
    public void withHeader_multiple() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .withHeader("UnitTest", "Spock")
                .withHeader("key", "value")
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        Assertions.assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        Assertions.assertThat(parametersSigning.getHeaderValues()).hasSize(2);
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("key", "value");

    }

    @Test
    public void withHeader_none() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        Assertions.assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        Assertions.assertThat(parametersSigning.getHeaderValues()).isEmpty();
    }

    @Test
    public void withHeader_encodingNone() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .withHeader("UnitTest", "Spock")
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersNone.class);
    }

    @Test
    public void validate_requiredKeys_jws() {

        Assertions.assertThatThrownBy(() -> JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS).build())
                .isInstanceOf(AtbashIllegalActionException.class);
    }

    @Test
    public void validate_requiredKeys_jwe() {

        AtbashKey rsa = new AtbashKey("somePath", new FakeRSAPrivate());
        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(rsa);

        Assertions.assertThatThrownBy(builder::build)
                .isInstanceOf(AtbashIllegalActionException.class)
                .hasMessage("(OCT-DEV-106) JWE encoding requires a JWK secret for the encryption");
    }

    @Test
    public void validate_requiredKeys_jwe_2() {

        AtbashKey rsa = new AtbashKey("somePath", new FakeRSAPrivate());
        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForEncryption(rsa);

        Assertions.assertThatThrownBy(builder::build)
                .isInstanceOf(AtbashIllegalActionException.class)
                .hasMessage("(OCT-DEV-112) JWE encoding requires a JWK secret for the signing");
    }

    @Test
    public void validate_requiredKeys_jwe_3() {

        AtbashKey rsa = new AtbashKey("somePath", new FakeRSAPrivate());
        AtbashKey ec = new AtbashKey("somePath", new FakeECPublic());
        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWE)
                .withSecretKeyForSigning(rsa)
                .withSecretKeyForEncryption(ec);

        JWTParameters parameters = builder.build();
        Assertions.assertThat(parameters).isInstanceOf(JWTParametersEncryption.class);
        JWTParametersEncryption parametersEncryption = (JWTParametersEncryption) parameters;
        Assertions.assertThat(parametersEncryption.getEncoding()).isEqualTo(JWTEncoding.JWE);

        Assertions.assertThat(parametersEncryption.getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(parametersEncryption.getParametersSigning().getKeyType()).isEqualTo(KeyType.RSA);
    }


    @Test
    public void JWKKeyType_RSA() {


        AtbashKey rsa = new AtbashKey("somePath", new FakeRSAPrivate());
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(rsa)
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        Assertions.assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        Assertions.assertThat(parametersSigning.getKeyType()).isEqualTo(KeyType.RSA);

    }

    @Test
    public void JWKKeyType_hmac() {

        byte[] secret = new byte[16];
        new SecureRandom().nextBytes(secret);

        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("hmacKeyId", "secret".getBytes(StandardCharsets.UTF_8));

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(atbashKey)
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;
        Assertions.assertThat(parametersSigning.getEncoding()).isEqualTo(JWTEncoding.JWS);

        Assertions.assertThat(parametersSigning.getKeyType()).isEqualTo(KeyType.OCT);

    }

    @Test
    public void withHeader_defaultValue() {
        System.setProperty("default.provider.1", "value1");
        System.setProperty("default.provider.2", "value2");

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .withHeader("UnitTest", "Spock")
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;

        Assertions.assertThat(parametersSigning.getHeaderValues()).hasSize(3);
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("default-key1", "value1");
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("default-key2", "value");

        System.setProperty("default.provider.1", "");
        System.setProperty("default.provider.2", "");
    }

    @Test
    public void withHeader_jkuValue() {

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey("testSecret", "Spock".getBytes(StandardCharsets.UTF_8)))
                .withHeader("UnitTest", "Spock")
                .withJSONKeyURL("jku_value")
                .build();

        Assertions.assertThat(parameters).isInstanceOf(JWTParametersSigning.class);
        JWTParametersSigning parametersSigning = (JWTParametersSigning) parameters;

        Assertions.assertThat(parametersSigning.getHeaderValues()).hasSize(2);
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("UnitTest", "Spock");
        Assertions.assertThat(parametersSigning.getHeaderValues()).containsEntry("jku", "jku_value");

    }
}