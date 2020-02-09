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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEProvider;

import java.util.Set;


/**
 * JSON Web Signature (JWS) provider
 *
 * <p>The JWS provider can be queried to determine its algorithm capabilities.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public interface JWSProvider extends JOSEProvider {


    /**
     * Returns the names of the supported algorithms by the JWS provider
     * instance. These correspond to the {@code alg} JWS header parameter.
     *
     * @return The supported JWS algorithms, empty set if none.
     */
    Set<JWSAlgorithm> supportedJWSAlgorithms();
}
