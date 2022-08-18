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


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;


/**
 * Tests JOSE object methods.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JOSEObjectTest {


    @Test
    public void testSplitThreeParts() {

        // Implies JWS
        String data = "abc.def.ghi";

        Assertions.assertThatCode(() -> {

            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(3);

            Assertions.assertThat(parts[0].toString()).isEqualTo("abc");
            Assertions.assertThat(parts[1].toString()).isEqualTo("def");
            Assertions.assertThat(parts[2].toString()).isEqualTo("ghi");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testSplitFiveParts() {

        // Implies JWE
        String data = "abc.def.ghi.jkl.mno";

        Assertions.assertThatCode(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(5);

            Assertions.assertThat(parts[0].toString()).isEqualTo("abc");
            Assertions.assertThat(parts[1].toString()).isEqualTo("def");
            Assertions.assertThat(parts[2].toString()).isEqualTo("ghi");
            Assertions.assertThat(parts[3].toString()).isEqualTo("jkl");
            Assertions.assertThat(parts[4].toString()).isEqualTo("mno");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testSplitEmptyThirdPart() {

        // Implies plain JOSE object
        String data = "abc.def.";

        Assertions.assertThatCode(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(3);

            Assertions.assertThat(parts[0].toString()).isEqualTo("abc");
            Assertions.assertThat(parts[1].toString()).isEqualTo("def");
            Assertions.assertThat(parts[2].toString()).isEqualTo("");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testSplitMissingDotForPlain() {

        // Implies plain JOSE object
        String data = "abc.def";

        Assertions.assertThatCode(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(3);

            Assertions.assertThat(parts[0].toString()).isEqualTo("abc");
            Assertions.assertThat(parts[1].toString()).isEqualTo("def");
            Assertions.assertThat(parts[2].toString()).isEqualTo("");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testSplitEmptySecondPart() {

        // JWS with empty payload
        String data = "abc..ghi";

        Assertions.assertThatCode(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(3);

            Assertions.assertThat(parts[0].toString()).isEqualTo("abc");
            Assertions.assertThat(parts[1].toString()).isEqualTo("");
            Assertions.assertThat(parts[2].toString()).isEqualTo("ghi");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testSplitEmptyFiveParts() {

        // JWS with empty payload
        String data = "....";

        Assertions.assertThatCode(() -> {
            Base64URLValue[] parts = JOSEObject.split(data);

            Assertions.assertThat(parts.length).isEqualTo(5);

            Assertions.assertThat(parts[0].toString()).isEqualTo("");
            Assertions.assertThat(parts[1].toString()).isEqualTo("");
            Assertions.assertThat(parts[2].toString()).isEqualTo("");
            Assertions.assertThat(parts[3].toString()).isEqualTo("");
            Assertions.assertThat(parts[4].toString()).isEqualTo("");
        }).doesNotThrowAnyException();
    }

    @Test
    public void testMIMETypes() {

        Assertions.assertThat(JOSEObject.MIME_TYPE_COMPACT).isEqualTo("application/jose; charset=UTF-8");
        Assertions.assertThat(JOSEObject.MIME_TYPE_JS).isEqualTo("application/jose+json; charset=UTF-8");
    }

    @Test
    public void testEquality_case() {

        Assertions.assertThat(new JOSEObjectType("at+jwt")).isEqualTo(new JOSEObjectType("at+jwt"));
        Assertions.assertThat(new JOSEObjectType("at+jwt")).isEqualTo(new JOSEObjectType("AT+JWT"));
        Assertions.assertThat(new JOSEObjectType("AT+JWT")).isEqualTo(new JOSEObjectType("AT+JWT"));
    }

    @Test
    public void testHashCode_case() {

        Assertions.assertThat(new JOSEObjectType("at+jwt").hashCode()).isEqualTo(new JOSEObjectType("at+jwt").hashCode());
        Assertions.assertThat(new JOSEObjectType("AT+JWT").hashCode()).isEqualTo(new JOSEObjectType("at+jwt").hashCode());
        Assertions.assertThat(new JOSEObjectType("AT+JWT").hashCode()).isEqualTo(new JOSEObjectType("AT+JWT").hashCode());
    }
}
