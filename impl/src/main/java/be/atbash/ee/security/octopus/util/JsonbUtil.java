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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.jwt.serializer.spi.SerializerProvider;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;

public final class JsonbUtil {

    private JsonbUtil() {
    }

    public static Jsonb getJsonb() {
        JsonbConfig config = new JsonbConfig();
        config.withDeserializers(SerializerProvider.getInstance().getDeserializers());
        config.withSerializers(SerializerProvider.getInstance().getSerializers());
        return JsonbBuilder.create(config);
    }
}
