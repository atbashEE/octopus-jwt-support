/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class SecretKeyTypeTest {

    @Test
    public void fromKey_rsaPublic() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeRSAPublic());
        assertThat(keyType).isNotNull();
        assertThat(keyType.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(keyType.isAsymmetric()).isTrue();
        assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);

    }

    @Test
    public void fromKey_rsaPrivate() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeRSAPrivate());
        assertThat(keyType).isNotNull();
        assertThat(keyType.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(keyType.isAsymmetric()).isTrue();
        assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);
    }

    @Test
    public void fromKey_ecPublic() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeECPublic());
        assertThat(keyType).isNotNull();
        assertThat(keyType.getKeyType()).isEqualTo(KeyType.EC);
        assertThat(keyType.isAsymmetric()).isTrue();
        assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PUBLIC);
    }

    @Test
    public void fromKey_ecPrivate() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeECPrivate());
        assertThat(keyType).isNotNull();
        assertThat(keyType.getKeyType()).isEqualTo(KeyType.EC);
        assertThat(keyType.isAsymmetric()).isTrue();
        assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.PRIVATE);
    }

    @Test
    public void fromKey_secretType() {
        SecretKeyType keyType = SecretKeyType.fromKey(new FakeSecretKey());
        assertThat(keyType).isNotNull();
        assertThat(keyType.getKeyType()).isEqualTo(KeyType.OCT);
        assertThat(keyType.isAsymmetric()).isFalse();
        assertThat(keyType.getAsymmetricPart()).isEqualTo(AsymmetricPart.SYMMETRIC);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_1() {
        // OCT type, asymmetric specified
        new SecretKeyType(KeyType.OCT, AsymmetricPart.PRIVATE);
    }

    @Test
    public void init_2() {
        // OCT type, no asymmetric
        new SecretKeyType(KeyType.OCT, AsymmetricPart.SYMMETRIC);
        new SecretKeyType(KeyType.OCT);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_3() {
        // RSA type, no asymmetric
        new SecretKeyType(KeyType.RSA, null);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_4() {
        // EC type, no asymmetric
        new SecretKeyType(KeyType.EC, null);
    }

    @Test
    public void init_5() {
        // RSA type, with asymmetric
        new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE);
        new SecretKeyType(KeyType.EC, AsymmetricPart.PUBLIC);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_6() {
        // RSA type, no asymmetric
        new SecretKeyType(KeyType.RSA);
        new SecretKeyType(KeyType.EC, AsymmetricPart.PUBLIC);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_7() {
        // EC type, no asymmetric
        new SecretKeyType(KeyType.EC);
    }

}