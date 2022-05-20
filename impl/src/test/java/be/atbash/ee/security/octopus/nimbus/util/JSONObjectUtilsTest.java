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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import jakarta.json.*;
import org.assertj.core.api.Assertions;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Tests the JSON object utilities.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
class JSONObjectUtilsTest {

    @Test
    void testParseTrailingWhiteSpace()
            throws Exception {

        Assertions.assertThat(JSONObjectUtils.parse("{} ").size()).isEqualTo(0);
        Assertions.assertThat(JSONObjectUtils.parse("{}\n").size()).isEqualTo(0);
        Assertions.assertThat(JSONObjectUtils.parse("{}\r\n").size()).isEqualTo(0);
    }


    @Test
    void testGetURI() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", "https://c2id.net");
        Assertions.assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isEqualTo(URI.create("https://c2id.net"));
    }

    @Test
    void testGetURI_null() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        Assertions.assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }

    @Test
    void testGetURI_missing() throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        Assertions.assertThat(JSONObjectUtils.getURI(builder.build(), "key")).isNull();
    }


    @Test
    void testGetStringList() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
        Assertions.assertThat(JSONObjectUtils.getStringList(jsonObject, "key")).containsExactly("apple", "pear");
    }

    @Test
    void testGetStringList_null() {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        Assertions.assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isEmpty();
    }

    @Test
    void testGetStringList_missing() {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        Assertions.assertThat(JSONObjectUtils.getStringList(builder.build(), "key")).isEmpty();
    }

    @Test
    void testGetStringList_wrongType() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"crit\":[123,321]}");
        Assertions.assertThatThrownBy(() -> JSONObjectUtils.getStringList(jsonObject, "crit"))
                .isInstanceOf(IncorrectJsonValueException.class)
                .hasMessage("JSON key 'crit' is expected to be an array of String");
    }

    @Test
    void testAsJsonArray() {
        List<String> data = new ArrayList<>();
        data.add("item1");
        data.add("item2");
        data.add("item3");
        JsonArray array = JSONObjectUtils.toJsonArray(data);

        Assertions.assertThat(array.toString()).isEqualTo("[\"item1\",\"item2\",\"item3\"]");
    }

    @Test
    void testAsJsonArray_empty() {
        List<String> data = new ArrayList<>();
        JsonArray array = JSONObjectUtils.toJsonArray(data);

        Assertions.assertThat(array.toString()).isEqualTo("[]");
    }

    @Test
    void testGetEnum() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", JWTEncoding.JWS.name());
        JsonObject jsonObject = builder.build();
        JWTEncoding value = JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class);

        Assertions.assertThat(value).isEqualTo(JWTEncoding.JWS);
    }

    @Test
    void testGetEnum_invalid() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key", "something");
        JsonObject jsonObject = builder.build();

        Assertions.assertThatThrownBy(() -> JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class))
                .isInstanceOf(IncorrectJsonValueException.class);

    }

    @Test
    void testGetEnum_null() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.addNull("key");
        JsonObject jsonObject = builder.build();
        JWTEncoding value = JSONObjectUtils.getEnum(jsonObject, "key", JWTEncoding.class);
        Assertions.assertThat(value).isNull();
    }

    @Test
    void addValue() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        JSONObjectUtils.addValue(builder, "stringKey", "someString");
        JSONObjectUtils.addValue(builder, "longKey", 123456L);
        JSONObjectUtils.addValue(builder, "intKey", 123);
        JSONObjectUtils.addValue(builder, "boolKey", Boolean.TRUE);

        String data = builder.build().toString();
        Assertions.assertThat(data).isEqualTo("{\"stringKey\":\"someString\",\"longKey\":123456,\"intKey\":123,\"boolKey\":true}");
    }

    @Test
    void remove() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key1", "value1");
        builder.add("key2", "value2");

        JsonObject jsonObject1 = builder.build();
        JsonObject jsonObject2 = JSONObjectUtils.remove(jsonObject1, "key1");

        Assertions.assertThat(jsonObject2.keySet()).containsOnly("key2");

    }

    @Test
    void remove_nonExistentKey() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("key1", "value1");
        builder.add("key2", "value2");

        JsonObject jsonObject1 = builder.build();
        JsonObject jsonObject2 = JSONObjectUtils.remove(jsonObject1, "key3");

        Assertions.assertThat(jsonObject2.keySet()).contains("key1", "key2");

    }

    @Test
    void getJsonValueAsObject_string() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
        Object value = JSONObjectUtils.getJsonValueAsObject(jsonObject.getJsonArray("key"));
        Assertions.assertThat(value).isInstanceOf(List.class);
        List<String> items = (List<String>) value;
        Assertions.assertThat(items).containsExactly("apple", "pear");
    }

    @Test
    void getJsonValueAsObject_int() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[123,321]}");
        Object value = JSONObjectUtils.getJsonValueAsObject(jsonObject.getJsonArray("key"));
        Assertions.assertThat(value).isInstanceOf(List.class);
        List<Integer> items = (List<Integer>) value;
        Assertions.assertThat(items).containsExactly(123, 321);
    }

    @Test
    void getJsonValueAsObject_mixed() throws ParseException {

        JsonObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",321]}");

        Assertions.assertThatThrownBy(() -> JSONObjectUtils.getJsonValueAsObject(jsonObject.getJsonArray("key")))
                .isInstanceOf(IncorrectJsonValueException.class)
                .hasMessage("JSONArray is expected to be an array of only String or Number");

    }

    @Test
    void mapToJsonObject() {
        Map<String, Object> data = new HashMap<>();

        Map<String, Object> data2 = new HashMap<>();
        data2.put("key", "value");

        data.put("map", data2);
        data.put("list", List.of("abc", "def"));
        data.put("long", 12345L);
        data.put("int", 123);
        data.put("double", 43.21D);
        data.put("float", 6543.98F);
        data.put("boolean", Boolean.TRUE);
        data.put("string", "someValue");
        data.put("pojo", new Pojo());
        data.put("null", null);
        JsonObject jsonObject = JSONObjectUtils.mapToJsonObject(data);
        Assertions.assertThat(jsonObject.keySet()).containsOnly("map", "list", "long", "int", "double", "float", "boolean", "string");

        JsonValue jsonValue = jsonObject.get("long");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).longValue()).isEqualTo(12345L);

        jsonValue = jsonObject.get("int");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).longValue()).isEqualTo(123L);

        jsonValue = jsonObject.get("double");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).doubleValue()).isEqualTo(43.21D);

        jsonValue = jsonObject.get("float");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).doubleValue()).isCloseTo(6543.98D, Offset.offset(0.001));

        jsonValue = jsonObject.get("boolean");
        Assertions.assertThat(jsonValue).isEqualTo(JsonValue.TRUE);

        jsonValue = jsonObject.get("string");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonString.class);
        Assertions.assertThat(((JsonString) jsonValue).getString()).isEqualTo("someValue");

        jsonValue = jsonObject.get("map");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonObject.class);

        jsonValue = jsonObject.get("list");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonArray.class);

        List<JsonString> jsonStrings = ((JsonArray) jsonValue).getValuesAs(JsonString.class);
        List<String> stringList = jsonStrings.stream().map(JsonString::getString).collect(Collectors.toList());
        Assertions.assertThat(stringList).isEqualTo(List.of("abc", "def"));
    }

    @Test
    void getAsJsonValue_String() {
        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue("someValue");
        Assertions.assertThat(jsonValue).isInstanceOf(JsonString.class);
        Assertions.assertThat(((JsonString) jsonValue).getString()).isEqualTo("someValue");

    }

    @Test
    void getAsJsonValue_longAndInt() {
        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue(123L);
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).longValue()).isEqualTo(123L);

        jsonValue = JSONObjectUtils.getAsJsonValue(543);
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).longValue()).isEqualTo(543L);
    }

    @Test
    void getAsJsonValue_doubleAndFloat() {
        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue(543.21D);
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).doubleValue()).isEqualTo(543.21D);

        jsonValue = JSONObjectUtils.getAsJsonValue(6543.98F);
        Assertions.assertThat(jsonValue).isInstanceOf(JsonNumber.class);
        Assertions.assertThat(((JsonNumber) jsonValue).doubleValue()).isCloseTo(6543.98D, Offset.offset(0.001));
    }

    @Test
    void getAsJsonValue_boolean() {
        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue(Boolean.TRUE);
        Assertions.assertThat(jsonValue).isEqualTo(JsonNumber.TRUE);

        jsonValue = JSONObjectUtils.getAsJsonValue(Boolean.FALSE);
        Assertions.assertThat(jsonValue).isEqualTo(JsonNumber.FALSE);

    }

    @Test
    void getAsJsonValue_collection() {
        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue(List.of("abc", "def"));
        Assertions.assertThat(jsonValue).isInstanceOf(JsonArray.class);

        List<JsonString> jsonStrings = ((JsonArray) jsonValue).getValuesAs(JsonString.class);
        List<String> stringList = jsonStrings.stream().map(JsonString::getString).collect(Collectors.toList());
        Assertions.assertThat(stringList).isEqualTo(List.of("abc", "def"));

        jsonValue = JSONObjectUtils.getAsJsonValue(Set.of(1234L, 5678L));
        Assertions.assertThat(jsonValue).isInstanceOf(JsonArray.class);

        List<JsonNumber> jsonNumbers = ((JsonArray) jsonValue).getValuesAs(JsonNumber.class);
        List<Long> longList = jsonNumbers.stream().map(JsonNumber::longValue).collect(Collectors.toList());
        Assertions.assertThat(longList).containsOnly(1234L, 5678L);
    }

    @Test
    void getAsJsonValue_map() {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");

        JsonValue jsonValue = JSONObjectUtils.getAsJsonValue(data);
        Assertions.assertThat(jsonValue).isInstanceOf(JsonObject.class);

    }

    @Test
    void getAsList_DelimitedString() {
        List<String> list = JSONObjectUtils.getAsList("abc,def");
        Assertions.assertThat(list).containsOnly("abc", "def");
    }

    @Test
    void getAsList_SingleString() {
        List<String> list = JSONObjectUtils.getAsList("abc");
        Assertions.assertThat(list).containsOnly("abc");
    }

    @Test
    void getAsList_DelimitedJsonString() {
        List<String> list = JSONObjectUtils.getAsList(Json.createValue("abc,def"));
        Assertions.assertThat(list).containsOnly("abc", "def");
    }

    @Test
    void getAsList_SingleJsonString() {
        List<String> list = JSONObjectUtils.getAsList(Json.createValue("abc"));
        Assertions.assertThat(list).containsOnly("abc");
    }

    @Test
    void getAsList_jsonArray() {
        JsonArray array = Json.createArrayBuilder()
                .add("abc")
                .add("def")
                .build();
        List<String> list = JSONObjectUtils.getAsList(array);
        Assertions.assertThat(list).containsOnly("abc", "def");
    }

    private static class Pojo {
        @Override
        public String toString() {
            return "PojoToStringValue";
        }
    }
}
