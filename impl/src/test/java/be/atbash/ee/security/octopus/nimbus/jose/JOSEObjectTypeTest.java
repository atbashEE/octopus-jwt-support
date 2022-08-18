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
package be.atbash.ee.security.octopus.nimbus.jose;


import org.junit.jupiter.api.Test;

import org.assertj.core.api.Assertions;


/**
 * Tests the JOSE object type header parameter.
 */
public class JOSEObjectTypeTest {

    @Test
    public void testConstants() {

        Assertions.assertThat(JOSEObjectType.JOSE.getType()).isEqualTo("JOSE");
        Assertions.assertThat(JOSEObjectType.JOSE_JSON.getType()).isEqualTo("JOSE+JSON");
        Assertions.assertThat(JOSEObjectType.JWT.getType()).isEqualTo("JWT");
    }


    @Test
    public void testToString() {

        Assertions.assertThat(JOSEObjectType.JOSE.toString()).isEqualTo(JOSEObjectType.JOSE.getType());
        Assertions.assertThat(JOSEObjectType.JOSE_JSON.toString()).isEqualTo(JOSEObjectType.JOSE_JSON.getType());
        Assertions.assertThat(JOSEObjectType.JWT.toString()).isEqualTo(JOSEObjectType.JWT.getType());
    }

}
