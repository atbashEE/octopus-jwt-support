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
package be.atbash.ee.security.octopus.keys.json;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.keys.writer.KeyWriterFactory;
import be.atbash.json.JSONObject;
import be.atbash.json.writer.JSONWriter;
import be.atbash.util.base64.Base64Codec;

import java.io.IOException;

public class AtbashKeyWriter implements JSONWriter<AtbashKey> {

    private KeyWriterFactory keyWriterFactory;

    public AtbashKeyWriter() {
        keyWriterFactory = new KeyWriterFactory();
        keyWriterFactory.init();

    }

    @Override
    public <E extends AtbashKey> void writeJSONString(E value, Appendable out) throws IOException {
        KeyEncoderParameters parameters = new KeyEncoderParameters();

        byte[] bytes = keyWriterFactory.writeKeyAsJWK(value, parameters);

        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField("kid", value.getKeyId());
        jsonObject.appendField("key", Base64Codec.encodeToString(bytes, true));
        out.append(jsonObject.toJSONString());

    }
}
