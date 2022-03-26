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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.config.PemKeyEncryption;
import org.eclipse.microprofile.config.spi.ConfigSource;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ProgramConfigSource implements ConfigSource {

    public static PemKeyEncryption pemKeyEncryption = PemKeyEncryption.PKCS8;

    @Override
    public Map<String, String> getProperties() {
        return null;
    }

    @Override
    public String getValue(String key) {
        String result = null;
        if (key.equals("key.pem.encryption")) {
            result = pemKeyEncryption.name();
        }
        return result;
    }

    @Override
    public String getName() {
        return "ProgramConfigSource";
    }

    @Override
    public int getOrdinal() {
        return Integer.MAX_VALUE;  // Make sure we are always the first one.
    }

    @Override
    public Set<String> getPropertyNames() {
        return new HashSet<>();
    }
}
