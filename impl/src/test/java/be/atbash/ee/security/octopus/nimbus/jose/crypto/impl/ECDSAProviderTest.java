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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * @author Vladimir Dzhuvinov
 * @version 2018-03-28
 */
public class ECDSAProviderTest {

    @Test
    public void testSupportedAlgorithms() {

        assertThat(ECDSAProvider.SUPPORTED_ALGORITHMS).contains(JWSAlgorithm.ES256);
        assertThat(ECDSAProvider.SUPPORTED_ALGORITHMS).contains(JWSAlgorithm.ES256K);
        assertThat(ECDSAProvider.SUPPORTED_ALGORITHMS).contains(JWSAlgorithm.ES384);
        assertThat(ECDSAProvider.SUPPORTED_ALGORITHMS).contains(JWSAlgorithm.ES512);
        assertThat(ECDSAProvider.SUPPORTED_ALGORITHMS).hasSize(4);
    }
}
