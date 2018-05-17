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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import com.nimbusds.jose.jwk.KeyUse;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;

/**
 *
 */

public final class HmacSecretUtil {

    private HmacSecretUtil() {
    }

    public static AtbashKey generateSecretKey(String kid, byte[] key) {
        SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");

        return new AtbashKey(kid, new ArrayList<KeyUse>(), secretKey);

    }
}
