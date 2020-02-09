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


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the base Algorithm class.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class AlgorithmTest {


    @Test
    public void noneConstant() {

        assertThat(Algorithm.NONE.getName()).isEqualTo("none");
    }

    @Test
    public void testEquals() {

        assertThat(Algorithm.NONE.getName()).isEqualTo("none");

        assertThat(new Algorithm("none")).isEqualTo(Algorithm.NONE);
    }

    @Test
    public void testConstructor() {

        Algorithm alg = new Algorithm("my-alg");

        assertThat(alg.getName()).isEqualTo("my-alg");
        assertThat(alg.toString()).isEqualTo("my-alg");
    }

    @Test
    public void testEquality() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("my-alg");

        assertThat(alg1).isEqualTo(alg2);
    }


    @Test
    public void testInequality() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("your-alg");

        assertThat(alg1).isNotEqualTo(alg2);
    }


    @Test
    public void testHashCode() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("my-alg");

        assertThat(alg1.hashCode()).isEqualTo(alg2.hashCode());
    }

    @Test
    public void noneAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", Algorithm.NONE.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        assertThat(algorithm).isEqualTo(Algorithm.NONE);
    }

    @Test
    public void jwsAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", JWSAlgorithm.HS256.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void jweAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", JWEAlgorithm.A256KW.getName());
        builder.add("enc", EncryptionMethod.A256GCM.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        assertThat(algorithm).isEqualTo(JWEAlgorithm.A256KW);
    }

    @Test
    public void testParseAlgorithm_nullAlg() {

        Assertions.assertThrows(ParseException.class, () -> Algorithm.parseAlgorithm(Json.createObjectBuilder().build()));

    }

}
