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
package be.atbash.ee.security.octopus.nimbus.jose;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JOSE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-14
 */
public class JOSEObjectTest {


    @Test
    public void testSplitThreeParts() {

        // Implies JWS
        String data = "abc.def.ghi";

        Assertions.assertDoesNotThrow(() -> {

            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(3);

            assertThat(parts[0].toString()).isEqualTo("abc");
            assertThat(parts[1].toString()).isEqualTo("def");
            assertThat(parts[2].toString()).isEqualTo("ghi");
        });
    }

    @Test
    public void testSplitFiveParts() {

        // Implies JWE
        String data = "abc.def.ghi.jkl.mno";

        Assertions.assertDoesNotThrow(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(5);

            assertThat(parts[0].toString()).isEqualTo("abc");
            assertThat(parts[1].toString()).isEqualTo("def");
            assertThat(parts[2].toString()).isEqualTo("ghi");
            assertThat(parts[3].toString()).isEqualTo("jkl");
            assertThat(parts[4].toString()).isEqualTo("mno");
        });
    }

    @Test
    public void testSplitEmptyThirdPart() {

        // Implies plain JOSE object
        String data = "abc.def.";

        Assertions.assertDoesNotThrow(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(3);

            assertThat(parts[0].toString()).isEqualTo("abc");
            assertThat(parts[1].toString()).isEqualTo("def");
            assertThat(parts[2].toString()).isEqualTo("");
        });
    }

    @Test
    public void testSplitMissingDiotForPlain() {

        // Implies plain JOSE object
        String data = "abc.def";

        Assertions.assertDoesNotThrow(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(3);

            assertThat(parts[0].toString()).isEqualTo("abc");
            assertThat(parts[1].toString()).isEqualTo("def");
            assertThat(parts[2].toString()).isEqualTo("");
        });
    }

    @Test
    public void testSplitEmptySecondPart() {

        // JWS with empty payload
        String data = "abc..ghi";

        Assertions.assertDoesNotThrow(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(3);

            assertThat(parts[0].toString()).isEqualTo("abc");
            assertThat(parts[1].toString()).isEqualTo("");
            assertThat(parts[2].toString()).isEqualTo("ghi");
        });
    }

    @Test
    public void testSplitEmptyFiveParts() {

        // JWS with empty payload
        String data = "....";

        Assertions.assertDoesNotThrow(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            assertThat(parts.length).isEqualTo(5);

            assertThat(parts[0].toString()).isEqualTo("");
            assertThat(parts[1].toString()).isEqualTo("");
            assertThat(parts[2].toString()).isEqualTo("");
            assertThat(parts[3].toString()).isEqualTo("");
            assertThat(parts[4].toString()).isEqualTo("");
        });
    }

    @Test
    public void testMIMETypes() {

        assertThat(JOSEObject.MIME_TYPE_COMPACT).isEqualTo("application/jose; charset=UTF-8");
        assertThat(JOSEObject.MIME_TYPE_JS).isEqualTo("application/jose+json; charset=UTF-8");
    }

    @Test
    public void testEquality_case() {

        assertThat(new JOSEObjectType("at+jwt")).isEqualTo(new JOSEObjectType("at+jwt"));
        assertThat(new JOSEObjectType("at+jwt")).isEqualTo(new JOSEObjectType("AT+JWT"));
        assertThat(new JOSEObjectType("AT+JWT")).isEqualTo(new JOSEObjectType("AT+JWT"));
    }

    @Test
    public void testHashCode_case() {

        assertThat(new JOSEObjectType("at+jwt").hashCode()).isEqualTo(new JOSEObjectType("at+jwt").hashCode());
        assertThat(new JOSEObjectType("AT+JWT").hashCode()).isEqualTo(new JOSEObjectType("at+jwt").hashCode());
        assertThat(new JOSEObjectType("AT+JWT").hashCode()).isEqualTo(new JOSEObjectType("AT+JWT").hashCode());
    }
}
