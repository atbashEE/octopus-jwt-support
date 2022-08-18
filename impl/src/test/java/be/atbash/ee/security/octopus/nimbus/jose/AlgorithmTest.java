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


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

/**
 * Tests the base Algorithm class.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class AlgorithmTest {


    @Test
    public void noneConstant() {

        Assertions.assertThat(Algorithm.NONE.getName()).isEqualTo("none");
    }

    @Test
    public void testEquals() {

        Assertions.assertThat(Algorithm.NONE.getName()).isEqualTo("none");

        Assertions.assertThat(new Algorithm("none")).isEqualTo(Algorithm.NONE);
    }

    @Test
    public void testConstructor() {

        Algorithm alg = new Algorithm("my-alg");

        Assertions.assertThat(alg.getName()).isEqualTo("my-alg");
        Assertions.assertThat(alg.toString()).isEqualTo("my-alg");
    }

    @Test
    public void testEquality() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("my-alg");

        Assertions.assertThat(alg1).isEqualTo(alg2);
    }


    @Test
    public void testInequality() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("your-alg");

        Assertions.assertThat(alg1).isNotEqualTo(alg2);
    }


    @Test
    public void testHashCode() {

        Algorithm alg1 = new Algorithm("my-alg");
        Algorithm alg2 = new Algorithm("my-alg");

        Assertions.assertThat(alg1.hashCode()).isEqualTo(alg2.hashCode());
    }

    @Test
    public void noneAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, Algorithm.NONE.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        Assertions.assertThat(algorithm).isEqualTo(Algorithm.NONE);
    }

    @Test
    public void jwsAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, JWSAlgorithm.HS256.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        Assertions.assertThat(algorithm).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    public void jweAlgorithm() throws ParseException {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, JWEAlgorithm.A256KW.getName());
        builder.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A256GCM.getName());
        JsonObject json = builder.build();
        Algorithm algorithm = Algorithm.parseAlgorithm(json);
        Assertions.assertThat(algorithm).isEqualTo(JWEAlgorithm.A256KW);
    }

    @Test
    public void testParseAlgorithm_nullAlg() {

        Assertions.assertThatThrownBy(() -> Algorithm.parseAlgorithm(Json.createObjectBuilder().build()))
                .isInstanceOf(ParseException.class);

    }

}
