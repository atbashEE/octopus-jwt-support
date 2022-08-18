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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.fake.*;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 */

public class SecretKeyTypeTest {

    @Test
    public void fromKey_rsaPublic() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeRSAPublic());
        Assertions.assertThat(keyType).isNotNull();
        Assertions.assertThat(keyType.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(keyType.isAsymmetric()).isTrue();
        Assertions.assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);

    }

    @Test
    public void fromKey_rsaPrivate() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeRSAPrivate());
        Assertions.assertThat(keyType).isNotNull();
        Assertions.assertThat(keyType.getKeyType()).isEqualTo(KeyType.RSA);
        Assertions.assertThat(keyType.isAsymmetric()).isTrue();
        Assertions.assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);
    }

    @Test
    public void fromKey_ecPublic() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeECPublic());
        Assertions.assertThat(keyType).isNotNull();
        Assertions.assertThat(keyType.getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(keyType.isAsymmetric()).isTrue();
        Assertions.assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
    }

    @Test
    public void fromKey_ecPrivate() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeECPrivate());
        Assertions.assertThat(keyType).isNotNull();
        Assertions.assertThat(keyType.getKeyType()).isEqualTo(KeyType.EC);
        Assertions.assertThat(keyType.isAsymmetric()).isTrue();
        Assertions.assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);
    }

    @Test
    public void fromKey_secretType() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeSecretKey());
        Assertions.assertThat(keyType).isNotNull();
        Assertions.assertThat(keyType.getKeyType()).isEqualTo(KeyType.OCT);
        Assertions.assertThat(keyType.isAsymmetric()).isFalse();
        Assertions.assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.SYMMETRIC);
    }

    @Test
    public void init_1() {
        // OCT type, asymmetric specified
        Assertions.assertThatThrownBy(() -> new SecretKeyType(KeyType.OCT, AsymmetricPart.PRIVATE))
                .isInstanceOf(AtbashIllegalActionException.class);
    }

    @Test
    public void init_2() {
        // OCT type, no asymmetric
        Assertions.assertThatCode(
                () -> {
                    new SecretKeyType(KeyType.OCT, AsymmetricPart.SYMMETRIC);
                    new SecretKeyType(KeyType.OCT);
                }
        ).doesNotThrowAnyException();

    }

    @Test
    public void init_3() {
        // RSA type, no asymmetric
        Assertions.assertThatThrownBy(() -> new SecretKeyType(KeyType.RSA, null))
                .isInstanceOf(AtbashIllegalActionException.class);
    }

    @Test
    public void init_4() {
        // EC type, no asymmetric
        Assertions.assertThatThrownBy(() -> new SecretKeyType(KeyType.EC, null))
                .isInstanceOf(AtbashIllegalActionException.class);
    }

    @Test
    public void init_5() {
        Assertions.assertThatCode(
                () -> {
                    // RSA type, with asymmetric
                    new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);
                    new SecretKeyType(KeyType.EC, AsymmetricPart.PUBLIC);
                }).doesNotThrowAnyException();
    }

    @Test
    public void init_6() {
        // RSA type, no asymmetric
        Assertions.assertThatThrownBy(() -> new SecretKeyType(KeyType.RSA))
                .isInstanceOf(AtbashIllegalActionException.class);

    }

}