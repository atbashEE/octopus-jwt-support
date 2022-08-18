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


import be.atbash.ee.security.octopus.util.JsonbUtil;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import jakarta.json.*;
import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbException;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;


/**
 * JSON object helper methods for parsing and typed retrieval of member values.
 * <p></p>
 * Based on code by Vladimir Dzhuvinov
 */
@PublicAPI
public final class JSONObjectUtils {


    /**
     * Parses a JSON object with the option to limit the input string size.
     *
     * <p>Specific JSON to Java entity mapping (as per JSON Smart):
     *
     * <ul>
     *     <li>JSON true|false map to {@code java.lang.Boolean}.
     *     <li>JSON numbers map to {@code java.lang.Number}.
     *         <ul>
     *             <li>JSON integer numbers map to {@code long}.
     *             <li>JSON fraction numbers map to {@code double}.
     *         </ul>
     *     <li>JSON strings map to {@code java.lang.String}.
     *     <li>JSON arrays map to {@code java.util.List<Object>}.
     *     <li>JSON objects map to {@code java.util.Map<String,Object>}.
     * </ul>
     *
     * @param value The JSON object string to parse. Must not be
     *              {@code null}.
     * @return The JSON object.
     * @throws ParseException If the string cannot be parsed to a valid JSON
     *                        object.
     */
    public static JsonObject parse(String value)
            throws ParseException {
        return parse(value, -1);
    }

    /**
     * Parses a JSON object with the option to limit the input string size.
     *
     * <p>Specific JSON to Java entity mapping (as per JSON Smart):
     *
     * <ul>
     *     <li>JSON true|false map to {@code java.lang.Boolean}.
     *     <li>JSON numbers map to {@code java.lang.Number}.
     *         <ul>
     *             <li>JSON integer numbers map to {@code long}.
     *             <li>JSON fraction numbers map to {@code double}.
     *         </ul>
     *     <li>JSON strings map to {@code java.lang.String}.
     *     <li>JSON arrays map to {@code java.util.List<Object>}.
     *     <li>JSON objects map to {@code java.util.Map<String,Object>}.
     * </ul>
     *
     * @param value     The JSON object string to parse. Must not be
     *                  {@code null}.
     * @param sizeLimit The max allowed size of the string to parse. A
     *                  negative integer means no limit.
     * @return The JSON object.
     * @throws ParseException If the string cannot be parsed to a valid JSON
     *                        object.
     */
    public static JsonObject parse(String value, int sizeLimit)
            throws ParseException {

        if (sizeLimit >= 0 && value.length() > sizeLimit) {
            throw new ParseException("The parsed string is longer than the max accepted size of " + sizeLimit + " characters", 0);
        }

        JsonObject result;

        try {

            Jsonb jsonb = JsonbUtil.getJsonb();
            result = jsonb.fromJson(value, JsonObject.class);


        } catch (JsonbException e) {
            throw new ParseException("Invalid JSON: " + e.getMessage(), 0);
        } catch (StackOverflowError e) {
            throw new ParseException("Excessive JSON object and / or array nesting", 0);
        } catch (Throwable e) {
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

        String value = getString(jsonObject, key);

        if (value == null) {
            return null;
        }

        try {
            return new URI(value);

        } catch (URISyntaxException e) {

            throw new ParseException(e.getMessage(), 0);
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
    public static URI getURIRequired(JsonObject jsonObject, String key)
            throws ParseException {
        // USed by oauth2-oidc-sdk

        URI uri = getURI(jsonObject, key);
        if (uri == null) {
            throw new ParseException(String.format("Missing JSON object member with key '%s'", key), 0);
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
        return jsonArray.getValuesAs(jsonValue -> {
            if (jsonValue instanceof JsonString) {
                return ((JsonString) jsonValue).getString();
            }
            return jsonValue.toString();
        });

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

    public static Object getJsonValueAsObject(JsonValue value) {
        Object result = null;
        if (value == null) {
            return null;
        }
        switch (value.getValueType()) {

            case ARRAY:
                JsonArray jsonArray = (JsonArray) value;

                // Cannot use getAsList as that converts the Numbers to String.
                JsonValue.ValueType valueType = defineItemValueType(jsonArray);
                if (valueType == JsonValue.ValueType.STRING) {
                    result = jsonArray.getValuesAs(JsonString::getString);
                }
                if (valueType == JsonValue.ValueType.NUMBER) {
                    result = jsonArray.getValuesAs(JsonNumber::numberValue);
                }
                if (result == null) {
                    throw new IncorrectJsonValueException("JSONArray is expected to be an array of String or Number");
                }
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

    public static JsonValue getAsJsonValue(Object value) {
        JsonValue jsonValue = null;

        if (value instanceof JsonValue) {
            // This is already a JsonValue
            jsonValue = (JsonValue) value;
        } else if (value instanceof String) {
            jsonValue = Json.createValue(value.toString());
        } else if ((value instanceof Long) || (value instanceof Integer)) {
            jsonValue = Json.createValue(((Number) value).longValue());
        } else if (value instanceof Number) {
            jsonValue = Json.createValue(((Number) value).doubleValue());
        } else if (value instanceof Boolean) {
            jsonValue = (Boolean) value ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof Collection) {
            jsonValue = toJsonArray((Collection<?>) value);
        } else if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            JsonObject entryJsonObject = mapToJsonObject((Map<String, Object>) value);
            jsonValue = entryJsonObject;
        }

        return jsonValue;
    }

    public static JsonObject mapToJsonObject(Map<String, Object> map) {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if (entryValue instanceof Map) {
                @SuppressWarnings("unchecked")
                JsonObject entryJsonObject = mapToJsonObject((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if (entryValue instanceof List) {
                JsonArray array = (JsonArray) getAsJsonValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if (entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if (entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if (entryValue instanceof Boolean) {
                boolean flag = (Boolean) entryValue;
                builder.add(entry.getKey(), flag);
            } else if (entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    public static JsonArray toJsonArray(Collection<?> collection) {
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();

        for (Object element : collection) {
            if (element == null) {
                arrayBuilder.add(JsonValue.NULL);
            } else {
                arrayBuilder.add(getAsJsonValue(element));
            }
        }

        return arrayBuilder.build();
    }

    private static JsonValue.ValueType defineItemValueType(JsonArray jsonArray) {
        JsonValue.ValueType result = null;
        for (JsonValue jsonValue : jsonArray) {
            if (result == null) {
                result = jsonValue.getValueType();
            } else {
                if (result != jsonValue.getValueType()) {
                    throw new IncorrectJsonValueException("JSONArray is expected to be an array of only String or Number");
                }
            }
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
        String value = getString(jsonObject, key);
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        for (T en : enumClass.getEnumConstants()) {

            if (en.toString().equalsIgnoreCase(value)) {
                return en;
            }
        }

        throw new IncorrectJsonValueException(String.format("Unexpected value of JSON object member with key '%s' for enum %s", key, enumClass));
    }

    /**
     * Converts a String, JsonString or JsonArray to a List of Strings. Correct handles null as input and
     * returns an empty list.
     *
     * @param value The instance to convert.
     * @return The resulting List of Strings.
     */
    public static List<String> getAsList(Object value) {

        if (value == null) {
            return Collections.emptyList();
        }

        if (value instanceof JsonArray) {
            return ((JsonArray) value).getValuesAs(jsonValue -> {
                if (jsonValue instanceof JsonString) {
                    return ((JsonString) jsonValue).getString();
                }
                return jsonValue.toString();
            });
        }

        if (value instanceof List) {
            return (List<String>) value;
        }

        if (value instanceof Collection) {
            return new ArrayList<>((Collection<String>) value);
        }

        String tempValue;
        if (value instanceof JsonString) {
            tempValue = ((JsonString) value).getString();
        } else if (value instanceof String) {
            tempValue = ((String) value);
        } else {
            tempValue = value.toString();
        }
        return Arrays.stream(StringUtils.split(tempValue)).map(String::trim).collect(Collectors.toList());
    }

    /**
     * Gets a string member of a JSON object as {@link Base64URLValue}.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value as Base64URLValue, may be {@code null}.
     */
    public static Base64URLValue getBase64URL(JsonObject jsonObject, String key) {

        if (!jsonObject.containsKey(key)) {
            return null;
        }

        Base64URLValue result = null;
        JsonValue.ValueType valueType = jsonObject.get(key).getValueType();
        switch (valueType) {
            case NULL:
                // result null is fine.
                break;
            case STRING:
                String value = jsonObject.getString(key);

                if (value == null) {
                    return null;
                }

                result = new Base64URLValue(value);
                break;

            case ARRAY:
            case OBJECT:
            case NUMBER:
            case TRUE:
            case FALSE:
                throw new IncorrectJsonValueException(String.format("the type of %s must be String or NULL", key));
        }
        return result;
    }

    /**
     * Returns the String value of the Json member. If not available or member is not a String Json Type, returns null.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value as String, may be {@code null}.
     */
    public static String getString(JsonObject jsonObject, String key) {
        String result = null;
        if (jsonObject.containsKey(key) && jsonObject.get(key).getValueType() == JsonValue.ValueType.STRING) {
            result = jsonObject.getString(key);
        }
        return result;
    }

    /**
     * Prevents public instantiation.
     */
    private JSONObjectUtils() {
    }
}

