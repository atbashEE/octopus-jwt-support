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
package be.atbash.ee.security.octopus.nimbus.jwk;


import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Based on code by Vladimir Dzhuvinov
 */
public class KeyUseAndOpsConsistencyTest {

    @Test
    public void testBothNull() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(null, null)).isTrue();
    }

    @Test
    public void testUseNull() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(null, Collections.singleton(KeyOperation.SIGN))).isTrue();
    }

    @Test
    public void testOpsNull() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(KeyUse.SIGNATURE, null)).isTrue();
    }

    @Test
    public void testConsistentSignatureUse() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)))).isTrue();
    }

    @Test
    public void testConsistentEncryptionUse() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT)))).isTrue();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                new HashSet<>(Arrays.asList(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY)))).isTrue();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT, KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY)))).isTrue();
    }

    @Test
    public void testSignatureUseNotConsistent() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.ENCRYPT)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.DECRYPT)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.WRAP_KEY)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.UNWRAP_KEY)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.DERIVE_KEY)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                Collections.singleton(KeyOperation.DERIVE_BITS)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT))
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                new HashSet<>(Arrays.asList(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.SIGNATURE,
                new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT, KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
        )).isFalse();
    }

    @Test
    public void testEncryptionUseNotConsistent() {

        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                Collections.singleton(KeyOperation.SIGN)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                Collections.singleton(KeyOperation.VERIFY)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                Collections.singleton(KeyOperation.DERIVE_KEY)
        )).isFalse();
        assertThat(KeyUseAndOpsConsistency.areConsistent(
                KeyUse.ENCRYPTION,
                Collections.singleton(KeyOperation.DERIVE_BITS)
        )).isFalse();
    }
}
