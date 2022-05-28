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
package be.atbash.ee.security.octopus.nimbus.jwk;


import java.util.*;


/**
 * JWK {@code use} and {@code key_ops} consistency rules.
 *
 * <p>See https://tools.ietf.org/html/rfc7517#section-4.3
 *
 * Based on code by Vladimir Dzhuvinov
 */
class KeyUseAndOpsConsistency {


    /**
     * Defines the consistent key use / key operations mappings.
     */
    private static final Map<KeyUse, Set<KeyOperation>> MAP;


    static {
        Map<KeyUse, Set<KeyOperation>> map = new HashMap<>();
        map.put(
                KeyUse.SIGNATURE,
                new HashSet<>(Arrays.asList(
                        KeyOperation.SIGN,
                        KeyOperation.VERIFY)));
        map.put(
                KeyUse.ENCRYPTION,
                new HashSet<>(Arrays.asList(
                        KeyOperation.ENCRYPT,
                        KeyOperation.DECRYPT,
                        KeyOperation.WRAP_KEY,
                        KeyOperation.UNWRAP_KEY
                )));
        MAP = Collections.unmodifiableMap(map);
    }


    /**
     * Checks if the specified key use and key operations are consistent.
     *
     * @param use The key use. May be {@code null}.
     * @param ops The key operations. May be {@code null}.
     * @return {@code true} if consistent, else {@code false}.
     */
    static boolean areConsistent(KeyUse use, Set<KeyOperation> ops) {

        if (use == null || ops == null) {
            return true;
        }

        return MAP.get(use).containsAll(ops);
    }
}
