/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.json.JSONArray;
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.*;

public class KeyReaderJWKSet extends KeyReaderJWK {

    public List<AtbashKey> readResource(String path, KeyResourcePasswordLookup passwordLookup) {
        InputStream inputStream;
        try {
            // FIXME Should we first use .resourceExists ?
            inputStream = ResourceUtil.getInstance().getStream(path);
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

        return parseContent(path, passwordLookup, fileContent);

    }

    public List<AtbashKey> parseContent(String path, KeyResourcePasswordLookup passwordLookup, String fileContent) {
        List<AtbashKey> result = new ArrayList<>();
        JSONObject jsonObject = (JSONObject) JSONValue.parse(fileContent);
        JSONArray keys = (JSONArray) jsonObject.get("keys");
        try {
            Set<String> kids = new HashSet<>();
            for (Object key : keys) {
                if (!(key instanceof JSONObject)) {
                    throw new InvalidJWKSetFormatException("The \"keys\" JSON array must contain JSON objects only");
                }

                JSONObject jwkJson = (JSONObject) key;
                String kid = jwkJson.getAsString("kid");
                if (kids.contains(kid)) {
                    throw new InvalidJWKSetFormatException(String.format("The kid '%s' was found multiple times in the resource '%s'", kid, path));
                }
                kids.add(kid);
                result.addAll(parse(jwkJson, path, passwordLookup));
            }
        } catch (ParseException | JOSEException e) {
            // TODO We need another exception, indicating that loading failed
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

}
