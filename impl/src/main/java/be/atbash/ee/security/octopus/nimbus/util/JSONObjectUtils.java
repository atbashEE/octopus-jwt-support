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


import be.atbash.ee.security.octopus.util.JsonbUtil;

import javax.json.*;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


/**
 * JSON object helper methods for parsing and typed retrieval of member values.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public final class JSONObjectUtils {


    /**
     * Parses a JSON object.
     *
     * <p>Specific JSON string to JsonObject by JSONB.
     *
     * @param value The JSON object string to parse. Must not be {@code null}.
     * @return The JSON object.
     * @throws ParseException If the string cannot be parsed to a valid JSON
     *                        object.
     */
    public static JsonObject parse(String value)
            throws ParseException {

        JsonObject result;

        try {

            Jsonb jsonb = JsonbUtil.getJsonb();
            result = jsonb.fromJson(value, JsonObject.class);


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
     * Gets a string member of a JSON object as {@code java.net.URI}.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     * @throws ParseException If the value is not of the expected type.
     */
    public static URI getURIRequired(JsonObject jsonObject, String key)
            throws ParseException {
        // USed by oauth2-oidc-sdk

        URI uri = getURI(jsonObject, key);
        if (uri == null) {
            throw new ParseException(String.format("Missing JSON object member with key \"%s\"", key), 0);
        }
        return uri;
    }

    /**
     * Remove the key from the Json Object.
     * @param jsonObject The JsonObject
     * @param key The key to remove
     * @return The JsonObject with the key removed.
     */
    public static JsonObject remove(JsonObject jsonObject, String key) {
        JsonObjectBuilder result = Json.createObjectBuilder(jsonObject);
        result.remove(key);
        return result.build();
    }

    /**
     * Gets a string list member of a JSON object
     *
     * @param jsonObject   The JSON object. Must not be {@code null}.
     * @param key The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     */
    public static List<String> getStringList(JsonObject jsonObject, String key) {

        if (!hasValue(jsonObject, key)) {
            return new ArrayList<>();
        }
        JsonArray jsonArray = jsonObject.getJsonArray(key);

        checkItemType(key, jsonArray);
        return jsonArray.getValuesAs(JsonString::getString);

    }

    private static void checkItemType(String key, JsonArray jsonArray) {
        boolean validType = true;
        for (JsonValue jsonValue : jsonArray) {
            if (jsonValue.getValueType() != JsonValue.ValueType.STRING) {
                validType = false;
            }
        }
        if (!validType) {
            if (key == null) {
                throw new IncorrectJsonValueException("JSONArray is expected to be an array of String");
            } else {
                throw new IncorrectJsonValueException(String.format("JSON key '%s' is expected to be an array of String", key));

            }
        }
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
        if (value == null) {
            return null;
        }
        switch (value.getValueType()) {

            case ARRAY:
                JsonArray jsonArray = (JsonArray) value;

                checkItemType(null, jsonArray);
                result = jsonArray.getValuesAs(JsonString::getString);
                break;
            case OBJECT:
                result = value;
                break;
            case STRING:
                result = ((JsonString) value).getString();
                break;
            case NUMBER:
                JsonNumber jsonNumber = (JsonNumber) value;
                if (jsonNumber.isIntegral()) {

                    result = jsonNumber.numberValue();
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
            return;
        }
        if (value instanceof JsonArray) {
            builder.add(key, (JsonArray) value);
            return;  // Mainly for this case sine JsonArray is also Collection
        }
        if (value instanceof JsonValue) {
            builder.add(key, (JsonValue)value);
            return;
        }
        if (value instanceof String) {
            builder.add(key, Json.createValue(value.toString()));
            return;
        }
        if (value instanceof Integer) {
            builder.add(key, Json.createValue((Integer) value));
            return;
        }
        if (value instanceof Long) {
            builder.add(key, Json.createValue((Long) value));
            return;
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
        if (!hasValue(jsonObject, key)) {
            return null;
        }
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

