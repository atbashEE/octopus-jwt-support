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
package be.atbash.ee.security.octopus.keys.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.util.reflection.ClassUtils;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus JWT Support Configuration")
public class JwtSupportConfiguration extends AbstractConfiguration implements ModuleConfig {

    /**
     * The return value can also be a directory where multiple files are located (and retrieved).
     * @return
     */
    @ConfigEntry
    public String getKeysLocation() {
        return getOptionalValue("keys.location", String.class);
    }

    @ConfigEntry
    public Class<KeyResourcePasswordLookup> getPasswordLookupClass() {
        // FIXME Does a Class work here in the lookup?
        String passwordClass = getOptionalValue("lookup.password.class", "be.atbash.ee.security.octopus.keys.reader.password.ConfigKeyResourcePasswordLookup", String.class);
        return ClassUtils.forName(passwordClass);
    }

    @ConfigEntry
    public Class<KeyManager> getKeyManagerClass() {
        // FIXME Does a Class work here in the lookup?
        String keyManagerClass = getOptionalValue("key.manager.class", "be.atbash.ee.security.octopus.keys.LocalKeyManager", String.class);
        return ClassUtils.forName(keyManagerClass);
    }
}
