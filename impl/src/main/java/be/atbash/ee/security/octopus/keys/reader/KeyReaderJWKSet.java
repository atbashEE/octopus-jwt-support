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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.util.JsonbUtil;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.stream.JsonParsingException;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.*;

public class KeyReaderJWKSet extends KeyReaderJWK {

    @Override
    public List<AtbashKey> readResource(String path, KeyResourcePasswordLookup passwordLookup) {
        InputStream inputStream;
        try {
            ResourceUtil resourceUtil = ResourceUtil.getInstance();
            if (!resourceUtil.resourceExists(path)) {
                throw new ResourceNotFoundException(path);
            }

            inputStream = resourceUtil.getStream(path);
            if (inputStream == null) {
                throw new KeyResourceNotFoundException(path);
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        return parseContent(fileContent, path, passwordLookup);

    }

    public List<AtbashKey> parseContent(String fileContent, String path, KeyResourcePasswordLookup passwordLookup) {
        List<AtbashKey> result = new ArrayList<>();

        Jsonb jsonb = JsonbUtil.getJsonb();
        JsonObject jsonObject;
        try {
            jsonObject = jsonb.fromJson(fileContent, JsonObject.class);
        } catch (JsonParsingException e) {
            // Not a JSON, No error as this can be part of 'testing' out which type it is.
            return result;
        }

        if (!jsonObject.containsKey("keys")) {
            // If it is not a jwkSet JSON
            return result;
        }

        JsonArray keys = jsonObject.getJsonArray("keys");
        try {
            Set<String> kids = new HashSet<>();
            for (Object key : keys) {
                if (!(key instanceof JsonObject)) {
                    throw new InvalidJWKSetFormatException("The \"keys\" JSON array must contain JSON objects only");
                }

                JsonObject jwkJson = (JsonObject) key;
                String kid = jwkJson.getString("kid");
                if (kids.contains(kid)) {
                    throw new InvalidJWKSetFormatException(String.format("The kid '%s' was found multiple times in the resource '%s'", kid, path));
                }
                kids.add(kid);
                result.addAll(parse(jwkJson.toString(), path, passwordLookup));
            }
        } catch (ParseException e) {
            // TODO We need another exception, indicating that loading failed
            throw new AtbashUnexpectedException(e);
        }

        return result;
    }

}
