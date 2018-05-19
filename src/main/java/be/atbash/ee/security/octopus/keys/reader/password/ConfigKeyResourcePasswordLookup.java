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
package be.atbash.ee.security.octopus.keys.reader.password;

import be.atbash.config.exception.ConfigurationException;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class ConfigKeyResourcePasswordLookup implements KeyResourcePasswordLookup {

    private static String KEY_PREFIX = "atbash.key.pwd.";

    private Map<ConfigKey, char[]> passwords;

    public ConfigKeyResourcePasswordLookup() {
        passwords = readPasswordsFromConfig();
    }

    @Override
    public char[] getResourcePassword(String resourcePath) {
        checkDependencies();
        char[] result = new char[0];
        String path = stripPrefix(resourcePath);
        for (Map.Entry<ConfigKey, char[]> entry : passwords.entrySet()) {
            if (entry.getKey().isMatch(path, null)) {
                result = entry.getValue();
            }
        }
        return result;
    }

    // Make public in ResourceUtils?
    private static String stripPrefix(String resourcePath) {
        return resourcePath.substring(resourcePath.indexOf(":") + 1);
    }

    @Override
    public char[] getKeyPassword(String resourcePath, String keyId) {
        checkDependencies();
        char[] result = new char[0];
        String path = stripPrefix(resourcePath);
        for (Map.Entry<ConfigKey, char[]> entry : passwords.entrySet()) {
            if (entry.getKey().isMatch(path, keyId)) {
                result = entry.getValue();
            }
        }
        if (result.length == 0) {
            // try without the kid, maybe only PW specified on file level
            for (Map.Entry<ConfigKey, char[]> entry : passwords.entrySet()) {
                if (entry.getKey().isMatch(path, null)) {
                    result = entry.getValue();
                }
            }
        }
        return result;
    }

    private void checkDependencies() {
        // For Java SE Support
        if (passwords == null) {
            passwords = readPasswordsFromConfig();
        }
    }

    private Map<ConfigKey, char[]> readPasswordsFromConfig() {
        Map<ConfigKey, char[]> result = new HashMap<>();
        Config config = ConfigProvider.getConfig();
        if (config.getPropertyNames() == null) {
            return result;
        }
        for (String configKeyName : config.getPropertyNames()) {
            if (configKeyName.startsWith(KEY_PREFIX)) {
                String value = config.getValue(configKeyName, String.class);
                String[] parts = determineParts(configKeyName);
                if (parts.length == 1) {
                    result.put(new ConfigKey(parts[0]), value.toCharArray());
                } else {
                    // TODO Improve constructor by using array.
                    String alias;
                    try {
                        alias = URLDecoder.decode(parts[1], "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        throw new ConfigurationException(String.format("config key uses invalid encoding '%s'", parts[1]));
                    }
                    result.put(new ConfigKey(parts[0], alias), value.toCharArray());
                }
            }
        }
        return result;
    }

    @Override
    public String toString() {
        // For the startup logging.
        return "class "+ ConfigKeyResourcePasswordLookup.class.getName();
    }

    private String[] determineParts(String keyName) {
        return keyName.substring(KEY_PREFIX.length()).split("!", 2);
    }

    private class ConfigKey {
        private String path;
        private String keyId;

        public ConfigKey(String path, String keyId) {

            this.path = path;
            this.keyId = keyId;
        }

        public ConfigKey(String path) {
            this(path, null);
        }

        public String getPath() {
            return path;
        }

        public String getKeyId() {
            return keyId;
        }

        public boolean isMatch(String path, String keyId) {
            if (this.path.equals(path)) {
                if (this.keyId == null) {
                    return keyId == null;
                } else {
                    return this.keyId.equals(keyId);
                }
            }
            return false;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ConfigKey)) {
                return false;
            }

            ConfigKey configKey = (ConfigKey) o;

            if (!path.equals(configKey.path)) {
                return false;
            }
            return keyId != null ? keyId.equals(configKey.keyId) : configKey.keyId == null;
        }

        @Override
        public int hashCode() {
            int result = path.hashCode();
            result = 31 * result + (keyId != null ? keyId.hashCode() : 0);
            return result;
        }
    }
}
