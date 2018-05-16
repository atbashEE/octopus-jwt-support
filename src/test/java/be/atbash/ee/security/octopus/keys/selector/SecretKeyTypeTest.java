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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.util.exception.AtbashIllegalActionException;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

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
        assertThat(keyType.getAsymmetricPart()).isNull();
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void init_1() {
        // OCT type, asymmetric specified
        new SecretKeyType(KeyType.OCT, AsymmetricPart.PRIVATE);
    }

    @Test
    public void init_2() {
        // OCT type, no asymmetric
        new SecretKeyType(KeyType.OCT, null);
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

    private static class FakeRSAPublic implements RSAKey, PublicKey {

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public BigInteger getModulus() {
            return null;
        }
    }

    private static class FakeRSAPrivate implements RSAKey, PrivateKey {

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public BigInteger getModulus() {
            return null;
        }
    }

    private static class FakeECPublic implements ECPublicKey {

        @Override
        public ECPoint getW() {
            return null;
        }

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public ECParameterSpec getParams() {
            return null;
        }
    }

    private static class FakeECPrivate implements ECPrivateKey {
        @Override
        public BigInteger getS() {
            return null;
        }

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        @Override
        public ECParameterSpec getParams() {
            return null;
        }
    }

    private static class FakeSecretKey implements SecretKey {

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}