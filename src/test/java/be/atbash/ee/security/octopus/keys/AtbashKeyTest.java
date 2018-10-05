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
package be.atbash.ee.security.octopus.keys;

import be.atbash.config.util.ResourceUtils;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AtbashKeyTest {

    @Test
    public void GetKeyId() {

        AtbashKey key = new AtbashKey(ResourceUtils.CLASSPATH_PREFIX + "test.pem", null, null);

        assertThat(key.getKeyId()).isEqualTo("test");
    }

    @Test
    public void getKeyId_multiple_dot() {

        AtbashKey key = new AtbashKey(ResourceUtils.CLASSPATH_PREFIX + "test.pub.pem", null, null);

        assertThat(key.getKeyId()).isEqualTo("test.pub");
    }

    @Test
    public void getKeyId_no_extension() {

        AtbashKey key = new AtbashKey(ResourceUtils.CLASSPATH_PREFIX + "test", null, null);

        assertThat(key.getKeyId()).isEqualTo("test");

    }

}
