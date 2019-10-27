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


import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;
import javax.json.bind.JsonbException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;


/**
 * JSON object helper methods for parsing and typed retrieval of member values.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-11-06
 */
public class JSONObjectUtils {


    /**
     * Parses a JSON object.
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


    /**
     * Gets a string array member of a JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @param key        The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     * @throws ParseException If the value is not of the expected type.
     */
    public static String[] getStringArray(JsonObject jsonObject, String key)
            throws ParseException {

        JsonArray jsonArray = jsonObject.getJsonArray(key);

        if (jsonArray == null) {
            return null;
        }

        try {
            return jsonArray.toArray(new String[0]);

        } catch (ArrayStoreException e) {

            throw new ParseException("JSON object member with key \"" + key + "\" is not an array of strings", 0);
        }
    }


    /**
     * Gets a string list member of a JSON object
     *
     * @param o   The JSON object. Must not be {@code null}.
     * @param key The JSON object member key. Must not be {@code null}.
     * @return The JSON object member value, may be {@code null}.
     * @throws ParseException If the value is not of the expected type.
     */
    public static List<String> getStringList(final JsonObject o, final String key) throws ParseException {

        String[] array = getStringArray(o, key);

        if (array == null) {
            return null;
        }

        return Arrays.asList(array);
    }

    /**
     * Prevents public instantiation.
     */
    private JSONObjectUtils() {
    }
}

