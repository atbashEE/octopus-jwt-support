/*
 * Copyright 2017-2022 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.config;

import be.atbash.util.StringUtils;

import java.util.Locale;

/**
 *
 */

public enum PemKeyEncryption {

    PKCS8, PKCS1, NONE;

    public static PemKeyEncryption parse(String value) {
        PemKeyEncryption result = null;
        if (StringUtils.hasText(value)) {
            String modifiedValue = value.replace("#", "").toUpperCase(Locale.ENGLISH).trim();
            for (PemKeyEncryption pemKeyEncryption : PemKeyEncryption.values()) {
                if (pemKeyEncryption.name().equals(modifiedValue)) {
                    result = pemKeyEncryption;
                }
            }
        }
        return result;
    }
}
