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

import be.atbash.ee.security.octopus.exception.MissingPasswordLookupException;
import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.nimbus.jwk.*;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import be.atbash.ee.security.octopus.util.JsonbUtil;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.bind.Jsonb;
import javax.json.stream.JsonParsingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class KeyReaderJWK {

    public List<AtbashKey> readResource(String path, KeyResourcePasswordLookup passwordLookup) {
        List<AtbashKey> result;
        InputStream inputStream = null;
        try {
            ResourceUtil resourceUtil = ResourceUtil.getInstance();
            if (!resourceUtil.resourceExists(path)) {
                throw new ResourceNotFoundException(path);
            }

            inputStream = resourceUtil.getStream(path);
            if (inputStream == null) {
                throw new KeyResourceNotFoundException(path);
            }

            String fileContent = new Scanner(inputStream).useDelimiter("\\Z").next();

            result = parse(fileContent, path, passwordLookup);
        } catch (ParseException | IOException e) {
            throw new AtbashUnexpectedException(e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return result;

    }


    protected List<AtbashKey> parse(String json, String path, KeyResourcePasswordLookup passwordLookup) throws ParseException {

        Jsonb jsonb = JsonbUtil.getJsonb();
        JsonObject jwkJsonObject;
        try {
            jwkJsonObject = jsonb.fromJson(json, JsonObject.class);
        } catch (JsonParsingException e) {
            // Not a JSON, but as this can be part of 'testing' out which type it is.
            return new ArrayList<>();
        }

        JWK jwk;
        if (jwkJsonObject.get("enc") == null) {
            // not encrypted
            jwk = JWK.parse(json);

        } else {
            if (passwordLookup == null) {
                throw new MissingPasswordLookupException();
            }
            char[] password = passwordLookup.getKeyPassword(path, jwkJsonObject.getString("kid"));
            String decoded = EncryptionHelper.decode(jwkJsonObject.getString("enc"), password);

            JsonObject decodedJSON = jsonb.fromJson(decoded, JsonObject.class);

            JsonObjectBuilder merged = Json.createObjectBuilder();
            decodedJSON.forEach(merged::add);
            jwkJsonObject.forEach(merged::add);

            jwk = JWK.parse(merged.build().toString());
        }
        return processJWK(jwk);
    }

    private List<AtbashKey> processJWK(JWK jwk) {
        List<AtbashKey> result = new ArrayList<>();
        if (jwk instanceof AsymmetricJWK) {

            PrivateKey privateKey;
            if (jwk instanceof ECKey) {
                privateKey = ((ECKey) jwk).toECPrivateKey();
            } else {
                privateKey = ((AsymmetricJWK) jwk).toPrivateKey();
            }
            if (privateKey != null) {
                result.add(new AtbashKey(jwk.getKeyID(), privateKey));
            }
            PublicKey publicKey = ((AsymmetricJWK) jwk).toPublicKey();
            if (publicKey != null) {
                result.add(new AtbashKey(jwk.getKeyID(), publicKey));
            }
        }
        if (jwk instanceof OctetSequenceKey) {
            OctetSequenceKey octKey = (OctetSequenceKey) jwk;
            result.add(new AtbashKey(jwk.getKeyID(), octKey.toSecretKey()));
        }
        if (result.isEmpty() && jwk instanceof RSAKey) {
            // Support Payara because it has an old version of Nimbus which uses AssymmetricJWK
            PrivateKey privateKey = ((RSAKey) jwk).toPrivateKey();
            if (privateKey != null) {
                result.add(new AtbashKey(jwk.getKeyID(), privateKey));
            }
            PublicKey publicKey = ((RSAKey) jwk).toPublicKey();
            if (publicKey != null) {
                result.add(new AtbashKey(jwk.getKeyID(), publicKey));
            }

        }
        return result;
    }
}
