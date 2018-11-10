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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.util.StringUtils;
import be.atbash.util.ordered.Order;

import java.util.HashMap;
import java.util.Map;

@Order(10)
public class JWTParameterHeaderDefaultProvider1 implements JWTParameterHeaderDefaultProvider{

    @Override
    public Map<String, Object> defaultHeaderValues() {
        Map<String, Object> result = new HashMap<>();
        String property = System.getProperty("default.provider.1");
        if (StringUtils.hasText(property)) {
            result.put("default-key1", property);
            result.put("UnitTest", "Ignored");
        }
        return result;
    }
}
