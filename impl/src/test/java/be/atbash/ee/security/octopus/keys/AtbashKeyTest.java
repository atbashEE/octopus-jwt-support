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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.fake.FakeRSAPrivate;
import be.atbash.ee.security.octopus.keys.fake.FakeRSAPublic;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.util.resource.ResourceUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class AtbashKeyTest {

    @Test
    public void getKeyId() {

        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pem", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("test");
    }

    @Test
    public void getKeyId_multiple_dot() {

        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pub.pem", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("test.pub");
    }

    @Test
    public void getKeyId_no_extension() {

        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("test");
    }

    @Test
    public void getKeyId_DeepDirectoryStructure() {

        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "/path/with/keys/test.pem", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("/path/with/keys/test");
    }

    @Test
    public void getKeyId_filePrefix() {

        AtbashKey key = new AtbashKey(ResourceUtil.FILE_PREFIX + "/path/with/keys/test.pem", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("/path/with/keys/test");
    }

    @Test
    public void getKeyId_urlPrefix() {

        AtbashKey key = new AtbashKey(ResourceUtil.URL_PREFIX + "http://host:8080/path/to/test.pem", new FakeRSAPublic());

        Assertions.assertThat(key.getKeyId()).isEqualTo("/path/to/test");
    }

    @Test
    public void getIsMatch_match() {
        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pem", new FakeRSAPrivate());
        Assertions.assertThat(key.isMatch("test", AsymmetricPart.PRIVATE)).isTrue();
    }

    @Test
    public void getIsMatch_differentId() {
        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pem", new FakeRSAPrivate());
        Assertions.assertThat(key.isMatch("Other", AsymmetricPart.PRIVATE)).isFalse();
    }

    @Test
    public void getIsMatch_differentType() {
        AtbashKey key = new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pem", new FakeRSAPrivate());
        Assertions.assertThat(key.isMatch("test", AsymmetricPart.PUBLIC)).isFalse();
    }

    @Test
    public void create_missingPath() {
        Assertions.assertThatThrownBy( () -> new AtbashKey(null, new FakeRSAPrivate()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void create_missingKey() {
        Assertions.assertThatThrownBy(() -> new AtbashKey(ResourceUtil.CLASSPATH_PREFIX + "test.pem", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void RSA_specification_2048() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("test", 2048);
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("key length : 2048");
        }
    }

    @Test
    public void RSA_specification_3072() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("test", 3072);
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("key length : 3072");
        }
    }

    @Test
    public void RSA_specification_4096() {
        List<AtbashKey> keys = TestKeys.generateRSAKeys("test", 4096);
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("key length : 4096");
        }
    }

    @Test
    public void OCT_specification_256() {
        List<AtbashKey> keys = TestKeys.generateOCTKeys("test", 256);
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("key length : 256");
        }
    }

    @Test
    public void OCT_specification_512() {
        List<AtbashKey> keys = TestKeys.generateOCTKeys("test", 512);
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("key length : 512");
        }
    }

    @Test
    public void EC_specification_P256() {
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "P-256");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : P-256");
        }
    }

    @Test
    public void EC_specification_P521() {
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "P-521");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : P-521");
        }
    }

    @Test
    public void EC_specification_P256K() {
        // For the deprecated Curve.P256K
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "P-256K");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : secp256k1");
        }
    }

    @Test
    public void EC_specification_SECP256K1() {
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "secp256k1");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : secp256k1");
        }
    }


    @Test
    public void EC_specification_P384() {
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "P-384");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : P-384");
        }
    }

    @Test
    public void EC_specification_prime256v1() {
        List<AtbashKey> keys = TestKeys.generateECKeys("test", "prime256v1");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : P-256");
        }
    }

    @Test
    public void OKP_specification() {
        List<AtbashKey> keys = TestKeys.generateOKPKeys("test");
        for (AtbashKey key : keys) {
            Assertions.assertThat(key.getSpecification()).isEqualTo("Curve name : Ed25519");
        }
    }

}
