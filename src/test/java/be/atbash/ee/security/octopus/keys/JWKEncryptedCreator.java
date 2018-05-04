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
package be.atbash.ee.security.octopus.keys;

import be.atbash.config.util.ResourceUtils;
import be.atbash.ee.security.octopus.jwk.EncryptedJSONJWK;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import com.nimbusds.jose.jwk.JWK;

import java.util.List;

/**
 *
 */

public class JWKEncryptedCreator {

    public static void main(String[] args) {
        KeyReader keyReader = new KeyReader();
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtils.CLASSPATH_PREFIX + "secp256r1-key.pem", null);

        JWK jwk = JWKCreator.createJWK(keys);
        System.out.println(EncryptedJSONJWK.encryptedOutput(jwk, "atbash".toCharArray()));

    }
}
