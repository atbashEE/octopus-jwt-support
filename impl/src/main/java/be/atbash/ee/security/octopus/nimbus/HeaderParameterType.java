/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus;

import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.CompressionAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

public class HeaderParameterType {

    private final String name;
    private final Class<?> parameterType;

    private HeaderParameterType(String name, Class<?> parameterType) {
        this.name = name;
        this.parameterType = parameterType;
    }

    String getName() {
        return name;
    }

    private static final Set<String> HEADER_REGISTERED_PARAMETER_NAME;
    private static final Set<String> COMMON_JWT_HEADER_REGISTERED_PARAMETER_NAME;
    private static final Set<String> JWE_HEADER_REGISTERED_PARAMETER_NAME;

    private static final List<HeaderParameterType> ALL_REGISTERED_PARAMETERS;

    static {
        List<HeaderParameterType> temp = new ArrayList<>();
        temp.add(new HeaderParameterType("alg", Algorithm.class));
        temp.add(new HeaderParameterType("typ", JOSEObjectType.class));
        temp.add(new HeaderParameterType("cty", String.class));
        temp.add(new HeaderParameterType("crit", Set.class));

        HEADER_REGISTERED_PARAMETER_NAME = temp
                .stream()
                .map(HeaderParameterType::getName)
                .collect(Collectors.toSet());

        ALL_REGISTERED_PARAMETERS = new ArrayList<>(temp);

        temp.clear();

        temp.add(new HeaderParameterType("jku", URI.class));
        temp.add(new HeaderParameterType("jwk", JWK.class));
        temp.add(new HeaderParameterType("x5u", URI.class));
        temp.add(new HeaderParameterType("x5t256", Base64URLValue.class));
        temp.add(new HeaderParameterType("x5c", List.class));
        temp.add(new HeaderParameterType("kid", String.class));

        COMMON_JWT_HEADER_REGISTERED_PARAMETER_NAME = temp
                .stream()
                .map(HeaderParameterType::getName)
                .collect(Collectors.toSet());

        ALL_REGISTERED_PARAMETERS.addAll(temp);

        temp.clear();

        temp.add(new HeaderParameterType("enc", EncryptionMethod.class));
        temp.add(new HeaderParameterType("epk", JWK.class));
        temp.add(new HeaderParameterType("zip", CompressionAlgorithm.class));
        temp.add(new HeaderParameterType("apu", Base64URLValue.class));
        temp.add(new HeaderParameterType("apv", Base64URLValue.class));
        temp.add(new HeaderParameterType("p2s", Base64URLValue.class));
        temp.add(new HeaderParameterType("p2c", Integer.class));
        temp.add(new HeaderParameterType("iv", Base64URLValue.class));
        temp.add(new HeaderParameterType("tag", Base64URLValue.class));

        JWE_HEADER_REGISTERED_PARAMETER_NAME = temp
                .stream()
                .map(HeaderParameterType::getName)
                .collect(Collectors.toSet());

        ALL_REGISTERED_PARAMETERS.addAll(temp);
    }

    public static Set<String> getHeaderParameters() {
        return HEADER_REGISTERED_PARAMETER_NAME;
    }

    public static Set<String> getCommonJwtHeaderParameters() {
        return COMMON_JWT_HEADER_REGISTERED_PARAMETER_NAME;
    }

    public static Set<String> getJweHeaderParameters() {
        return JWE_HEADER_REGISTERED_PARAMETER_NAME;
    }

    public static <T> T getParameterValue(String name, T value, Map<String, Object> parameters) {
        T result = value;  // The value has precedence over the value in the parameter map.
        if (result == null) {
            HeaderParameterType parameterType = findHeaderParameterType(name);
            // in theory parameterType can be null
            if (parameterType == null) {
                return null;
            }
            // No parameters so no value can be defined at that level
            if (parameters == null) {
                return null;
            }
            // No value for the parameter, so null.
            Object mapValue = parameters.get(name);
            if (mapValue == null) {
                return null;
            }
            if (!parameterType.parameterType.isAssignableFrom(mapValue.getClass())) {
                throw new IllegalArgumentException(String.format("The type of the parameter \"%s\" must be %s.", name, parameterType.parameterType.getSimpleName()));
            }
            // Ok expected type
            result = (T) mapValue;
        }
        return result;
    }

    private static HeaderParameterType findHeaderParameterType(String name) {
        return ALL_REGISTERED_PARAMETERS.stream()
                .filter(hpt -> name.equals(hpt.name))
                .findAny().orElse(null);
    }

    public static Map<String, Object> filterOutRegisteredNames(Map<String, Object> parameters, Set<String> registeredNames) {
        if (parameters == null) {
            return new HashMap<>();
        }
        Map<String, Object> temp = new HashMap<>(parameters);
        registeredNames.forEach(temp::remove);
        return Collections.unmodifiableMap(temp);
    }
}
