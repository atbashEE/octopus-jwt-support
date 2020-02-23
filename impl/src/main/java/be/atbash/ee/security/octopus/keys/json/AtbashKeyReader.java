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
package be.atbash.ee.security.octopus.keys.json;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jwk.*;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.json.JsonObject;
import javax.json.bind.serializer.DeserializationContext;
import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.stream.JsonParser;
import java.lang.reflect.Type;
import java.text.ParseException;
import java.util.Base64;

public class AtbashKeyReader implements JsonbDeserializer<AtbashKey> {
    @Override
    public AtbashKey deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, Type type) {
        JsonObject jsonObject = jsonParser.getObject();

        AtbashKey.AtbashKeyBuilder builder = new AtbashKey.AtbashKeyBuilder();
        builder.withKeyId(jsonObject.getString("kid"));

        String key = new String(Base64.getDecoder().decode(jsonObject.getString("key")));

        try {
            boolean handled = false;
            JWK jwk = JWK.parse(key);
            if (KeyType.RSA.equals(jwk.getKeyType())) {
                RSAKey rsaKey = (RSAKey) jwk;
                if (rsaKey.isPrivate()) {
                    builder.withKey(rsaKey.toPrivateKey());
                } else {
                    builder.withKey(rsaKey.toPublicKey());
                }
                handled = true;
            }

            if (KeyType.EC.equals(jwk.getKeyType())) {
                ECKey ecKey = (ECKey) jwk;
                if (ecKey.isPrivate()) {
                    builder.withKey(ecKey.toPrivateKey());
                } else {
                    builder.withKey(ecKey.toECPublicKey());
                }
                handled = true;
            }

            if (KeyType.OCT.equals(jwk.getKeyType())) {
                OctetSequenceKey octKey = (OctetSequenceKey) jwk;
                builder.withKey(octKey.toSecretKey());
                handled = true;
            }

            if (KeyType.OKP.equals(jwk.getKeyType())) {
                OctetKeyPair okpKey = (OctetKeyPair) jwk;
                if (okpKey.isPrivate()) {
                    builder.withKey(okpKey.toPrivateKey());
                } else {
                    builder.withKey(okpKey.toPublicKey());
                }
                handled = true;
            }

            if (!handled) {
                throw new KeyTypeException(jwk.getKeyType(), "Key JSON deserialization ");
            }
        } catch (ParseException e) {
            throw new AtbashUnexpectedException(e);
        }

        return builder.build();
    }

}
