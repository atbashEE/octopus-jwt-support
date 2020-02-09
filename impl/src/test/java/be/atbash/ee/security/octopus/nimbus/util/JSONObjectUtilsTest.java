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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JSON object utilities.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JSONObjectUtilsTest {

    @Test
    public void testParseTrailingWhiteSpace()
            throws Exception {

        assertThat(JSONObjectUtils.parse("{} ").size()).isEqualTo(0);
        assertThat(JSONObjectUtils.parse("{}\n").size()).isEqualTo(0);
        assertThat(JSONObjectUtils.parse("{}\r\n").size()).isEqualTo(0);
    }


    @Test
    public void testGetURI() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", "https://c2id.net");
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isEqualTo(URI.create("https://c2id.net"));
    }

    @Test
    public void testGetURI_null() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }

    @Test
    public void testGetURI_missing() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }


    @Test
    public void testGetStringList() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
        assertThat(JSONObjectUtils.getStringList(jsonObject, "key")).containsExactly("apple", "pear");
    }

    @Test
    public void testGetStringList_null()  {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isEmpty();
    }

    @Test
    public void testGetStringList_missing()  {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isEmpty();
    }

    @Test
    public void testAsJsonArray() {
        List<String> data = new ArrayList<>();
        data.add("item1");
        data.add("item2");
        data.add("item3");
        JsonArray array = JSONObjectUtils.asJsonArray(data);

        assertThat(array.toString()).isEqualTo("[\"item1\",\"item2\",\"item3\"]");
    }

    @Test
    public void testAsJsonArray_empty() {
        List<String> data = new ArrayList<>();
        JsonArray array = JSONObjectUtils.asJsonArray(data);

        assertThat(array.toString()).isEqualTo("[]");
    }

    @Test
    public void testGetEnum() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", JWTEncoding.JWS.name());
        JsonObject jsonObject = builder.build();
        JWTEncoding value = JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class);

        assertThat(value).isEqualTo(JWTEncoding.JWS);
    }

    @Test
    public void testGetEnum_invalid() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", "something");
        JsonObject jsonObject = builder.build();
        Assertions.assertThrows(IncorrectJsonValueException.class, () -> JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class));
    }

    @Test
    public void testGetEnum_null() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        JsonObject jsonObject = builder.build();
        JWTEncoding value = JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class);
        assertThat(value).isNull();
    }

    @Test
    public void addValue() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        JSONObjectUtils.addValue(builder, "stringKey", "someString");
        JSONObjectUtils.addValue(builder, "longKey", 123456L);
        JSONObjectUtils.addValue(builder, "intKey", 123);
        JSONObjectUtils.addValue(builder, "boolKey", Boolean.TRUE);

        String data = builder.build().toString();
        assertThat(data).isEqualTo("{\"stringKey\":\"someString\",\"longKey\":123456,\"intKey\":123,\"boolKey\":true}");
    }

    @Test
    public void remove() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key1", "value1");
        builder.add("key2", "value2");

        JsonObject jsonObject1 = builder.build();
        JsonObject jsonObject2 = JSONObjectUtils.remove(jsonObject1, "key1");

        assertThat(jsonObject2.keySet()).containsOnly("key2");

    }

    @Test
    public void remove_nonExistentKey() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key1", "value1");
        builder.add("key2", "value2");

        JsonObject jsonObject1 = builder.build();
        JsonObject jsonObject2 = JSONObjectUtils.remove(jsonObject1, "key3");

        assertThat(jsonObject2.keySet()).contains("key1", "key2");

    }
}
