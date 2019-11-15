/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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


import javax.json.*;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;
import javax.json.bind.JsonbException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Collection;
import java.util.List;


/**
 * JSON object helper methods for parsing and typed retrieval of member values.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-11-06
 */
public final class JSONObjectUtils {


    /**
     * Parses a JSON object.
     *
     * <p>Specific JSON to Java entity mapping (as per JSON Smart): FIXME javadoc correction
     *
     * <ul>
     *     <li>JSON true|false map to {@code java.lang.Boolean}.
     *     <li>JSON numbers map to {@code java.lang.Number}.
     *         <ul>
     *             <li>JSON integer numbers map to {@code long}.
     *             <li>JSON fraction numbers map to {@code double}.
     *         </ul>
     *     <li>JSON strings map to {@code java.lang.String}.
     *     <li>JSON arrays map to {@code net.minidev.json.JSONArray}.
     *     <li>JSON objects map to {@code net.minidev.json.JSONObject}.
     * </ul>
     *
     * @param s The JSON object string to parse. Must not be {@code null}.
     * @return The JSON object.
     * @throws ParseException If the string cannot be parsed to a valid JSON
     *                        object.
     */
    public static JsonObject parse(String s)
            throws ParseException {

        JsonObject result;

        try {
            JsonbConfig config = new JsonbConfig();
            Jsonb jsonb = JsonbBuilder.create(config);

            result = jsonb.fromJson(s, JsonObject.class);


        } catch (JsonbException e) {

            throw new ParseException("Invalid JSON: " + e.getMessage(), 0);
        } catch (Exception e) {
            throw new ParseException("Unexpected exception: " + e.getMessage(), 0);
        }

        if (result != null) {
            return result;
        } else {
            throw new ParseException("JSON entity is not an object", 0);
        }
    }


    /**
     * Gets a string member of a JSON object as {@code java.net.URI}.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     * @throws ParseException If the value is not of the expected type.
     */
    public static URI getURI(JsonObject jsonObject, String key)
            throws ParseException {

        if (JSONObjectUtils.hasValue(jsonObject, key)) {
            String value = jsonObject.getString(key);

            if (value == null) {
                return null;
            }

            try {
                return new URI(value);

            } catch (URISyntaxException e) {

                throw new ParseException(e.getMessage(), 0);
            }
        }
        return null;
    }


    /**
     * Gets a string list member of a JSON object
     *
     * @param jsonObject   The JSON object. Must not be {@code null}.
     * @param key The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     */
    public static List<String> getStringList(JsonObject jsonObject, String key) {

        // FIXME Test what happens when using other values as Strings.
        if (!hasValue(jsonObject, key)) {
            return null;
        }
        JsonArray jsonArray = jsonObject.getJsonArray(key);

        return jsonArray.getValuesAs(JsonString::getString);

    }

    /**
     * Gets a String list as Json Array.
     *
     * @param data List of String items to be converted to Json Array.
     * @return JsonArray with the Data
     */
    public static JsonArray asJsonArray(List<String> data) {

        JsonArrayBuilder result = Json.createArrayBuilder();
        for (String item : data) {
            result.add(item);
        }

        return result.build();

    }

    public static Object getJsonValueAsObject(JsonValue value) {
        Object result = null;
        switch (value.getValueType()) {

            case ARRAY:
                // TODO We assume List of String
                JsonArray jsonArray = (JsonArray) value;
                result = jsonArray.getValuesAs(JsonString::getString);
                break;
            case OBJECT:
                /*
                JsonObject jsonObject = (JsonObject) value;
                result = jsonObject.entrySet().stream().collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> getJsonValueAsObject(e.getValue())));
                        */
                result = value;
                break;
            case STRING:
                result = ((JsonString) value).getString();
                break;
            case NUMBER:
                JsonNumber jsonNumber = (JsonNumber) value;
                if (jsonNumber.isIntegral()) {
                    result = jsonNumber.longValue();
                } else {
                    result = jsonNumber.doubleValue();
                }
                break;
            case TRUE:
                result = Boolean.TRUE;
                break;
            case FALSE:
                result = Boolean.FALSE;
                break;
            case NULL:
                break;
        }
        return result;
    }

    public static void addValue(JsonObjectBuilder builder, String key, Object value) {
        if (value instanceof JsonObject) {
            builder.add(key, (JsonObject) value);
        }
        if (value instanceof String) {
            builder.add(key, Json.createValue(value.toString()));
        }
        if (value instanceof Integer) {
            builder.add(key, Json.createValue((Integer) value));
        }
        if (value instanceof Long) {
            builder.add(key, Json.createValue((Long) value));
        }
        if (value instanceof Boolean) {
            Boolean bool = (Boolean) value;
            builder.add(key, bool ? JsonValue.TRUE : JsonValue.FALSE);
        }
        if (value instanceof Collection) {
            // We assume collection of String
            Collection<?> collection = (Collection<?>) value;
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            for (Object item : collection) {
                arrayBuilder.add(item.toString());
            }
            builder.add(key, arrayBuilder.build());
        }
        // FIXME Other types
    }

    public static boolean hasValue(JsonObject jsonObject, String key) {
        return jsonObject.containsKey(key) && jsonObject.get(key).getValueType() != JsonValue.ValueType.NULL;
    }

    /**
     * Gets a string member of a JSON object as an enumerated object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be
     *                   {@code null}.
     * @param enumClass  The enumeration class. Must not be {@code null}.
     * @return The member value.
     */
    public static <T extends Enum<T>> T getEnum(JsonObject jsonObject,
                                                String key,
                                                Class<T> enumClass) {

        String value = jsonObject.getString(key);

        for (T en : enumClass.getEnumConstants()) {

            if (en.toString().equalsIgnoreCase(value)) {
                return en;
            }
        }

        throw new IncorrectJsonValueException(String.format("Unexpected value of JSON object member with key \"%s\" for enum %s", key, enumClass.toString()));
    }

    /**
     * Prevents public instantiation.
     */
    private JSONObjectUtils() {
    }
}

