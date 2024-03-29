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
package be.atbash.ee.security.octopus.jwt.parameter;

import java.util.List;
import java.util.Map;

abstract class JWTParametersHeader implements JWTParameters {

    private final Map<String, Object> headerValues;

    JWTParametersHeader(Map<String, Object> headerValues) {
        this.headerValues = headerValues;
        addDefaults();
    }

    private void addDefaults() {
        List<JWTParameterHeaderDefaultProvider> defaultProviders = JWTParameterHeaderDefaultProviderServiceLoader.getDefaultProviders();
        for (JWTParameterHeaderDefaultProvider defaultProvider : defaultProviders) {
            Map<String, Object> values = defaultProvider.defaultHeaderValues();
            applyDefaults(values);
        }
    }

    private void applyDefaults(Map<String, Object> values) {
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (!headerValues.containsKey(entry.getKey())) {
                headerValues.put(entry.getKey(), entry.getValue());
            }
        }
    }

    public Map<String, Object> getHeaderValues() {
        return headerValues;
    }
}
