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
package be.atbash.ee.security.octopus.keys.json;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.keys.writer.KeyWriterFactory;

import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.bind.serializer.JsonbSerializer;
import javax.json.bind.serializer.SerializationContext;
import javax.json.stream.JsonGenerator;
import java.io.IOException;
import java.util.Base64;

public class AtbashKeyWriter implements JsonbSerializer<AtbashKey> {

    private KeyWriterFactory keyWriterFactory;
    private JsonBuilderFactory factory;

    public AtbashKeyWriter() {
        keyWriterFactory = new KeyWriterFactory();
        keyWriterFactory.init();
        factory = Json.createBuilderFactory(null);
    }

    @Override
    public void serialize(AtbashKey atbashKey, JsonGenerator jsonGenerator, SerializationContext serializationContext) {
        KeyEncoderParameters parameters = new KeyEncoderParameters();

        byte[] bytes = new byte[0];
        try {
            bytes = keyWriterFactory.writeKeyAsJWK(atbashKey, parameters);
        } catch (IOException e) {
            e.printStackTrace(); // FIXME
        }

        jsonGenerator.writeStartObject()
                .writeKey("kid").write(atbashKey.getKeyId())
                .writeKey("key").write(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes))
                .writeEnd();

    }
}
