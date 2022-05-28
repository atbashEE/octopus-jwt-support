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
package be.atbash.ee.security.octopus.jwt.serializer.spi;

import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.bind.serializer.JsonbSerializer;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

public final class SerializerProvider {

    private static final SerializerProvider INSTANCE = new SerializerProvider();

    private final List<JsonbSerializer<?>> serializers;
    private final List<JsonbDeserializer<?>> deserializers;

    private SerializerProvider() {
        serializers = new ArrayList<>();
        ServiceLoader.load(JsonbSerializer.class).forEach(serializers::add);

        deserializers = new ArrayList<>();
        ServiceLoader.load(JsonbDeserializer.class).forEach(deserializers::add);
    }

    public JsonbSerializer<?>[] getSerializers() {
        return serializers.toArray(new JsonbSerializer[0]);
    }

    public JsonbDeserializer<?>[] getDeserializers() {
        return deserializers.toArray(new JsonbDeserializer[0]);
    }

    public static SerializerProvider getInstance() {
        return INSTANCE;
    }
}
