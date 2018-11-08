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
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.json.writer.CustomBeanBuilderJSONEncoder;
import be.atbash.util.base64.Base64Codec;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

import java.text.ParseException;

public class AtbashKeyCustomBeanJSONEncoder extends CustomBeanBuilderJSONEncoder<AtbashKey, AtbashKey.AtbashKeyBuilder> {

    public AtbashKeyCustomBeanJSONEncoder() {
        super(AtbashKey.class, AtbashKey.AtbashKeyBuilder.class);
    }

    @Override
    public void setBuilderValue(AtbashKey.AtbashKeyBuilder atbashKeyBuilder, String key, Object value) {
        if ("kid".equals(key)) {
            atbashKeyBuilder.withKeyId(value.toString());
        }
        if ("key".equals(key)) {
            JSONObject jsonObject = (JSONObject) JSONValue.parse(new String(Base64Codec.decode(value.toString())));
            try {
                JWK jwk = JWK.parse(jsonObject.toJSONString());

                boolean handled = false;
                if (KeyType.RSA.equals(jwk.getKeyType())) {
                    RSAKey rsaKey = (RSAKey) jwk;
                    if (rsaKey.isPrivate()) {
                        atbashKeyBuilder.withKey(rsaKey.toPrivateKey());
                    } else {
                        atbashKeyBuilder.withKey(rsaKey.toPublicKey());
                    }
                    handled = true;
                }

                if (KeyType.EC.equals(jwk.getKeyType())) {
                    ECKey ecKey = (ECKey) jwk;
                    if (ecKey.isPrivate()) {
                        atbashKeyBuilder.withKey(ecKey.toPrivateKey());
                    } else {
                        atbashKeyBuilder.withKey(ecKey.toECPublicKey(BouncyCastleProviderSingleton.getInstance()));
                    }
                    handled = true;
                }

                if (!handled) {
                    throw new IllegalArgumentException(String.format("KeyType %s not supported.", jwk.getKeyType()));
                }
            } catch (ParseException | JOSEException e) {
                throw new AtbashUnexpectedException(e);
            }

        }
    }

    @Override
    public AtbashKey build(AtbashKey.AtbashKeyBuilder atbashKeyBuilder) {
        return atbashKeyBuilder.build();
    }
}
