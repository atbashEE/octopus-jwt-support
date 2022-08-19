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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.util.PublicAPI;

@PublicAPI
public enum KeyResourceType {
    JWK(".jwk", ".jwke"), JWKSET(".jwks", ".jwkset", ".jwksete"), PEM(".pem", ".der"), KEYSTORE(".jks", ".p12", ".pfx");

    private final String[] suffixes;

    KeyResourceType(String... suffixes) {
        this.suffixes = suffixes;
    }

    public String[] getSuffixes() {
        return suffixes;
    }

    public static KeyResourceType valueFor(String data) {
        KeyResourceType result = null;
        for (KeyResourceType value : KeyResourceType.values()) {
            if (value.name().equalsIgnoreCase(data)) {
                result = value;
            }
        }
        return result;
    }
}
