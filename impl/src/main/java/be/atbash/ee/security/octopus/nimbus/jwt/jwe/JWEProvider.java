/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEProvider;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JCAAware;
import be.atbash.ee.security.octopus.nimbus.jose.jca.JWEJCAContext;

import java.util.Set;


/**
 * JSON Web Encryption (JWE) provider.
 *
 * <p>The JWE provider can be queried to determine its algorithm capabilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-05-26
 */
public interface JWEProvider extends JOSEProvider, JCAAware<JWEJCAContext> {


    /**
     * Returns the names of the supported algorithms by the JWE provider
     * instance. These correspond to the {@code alg} JWE header parameter.
     *
     * @return The supported JWE algorithms, empty set if none.
     */
    Set<JWEAlgorithm> supportedJWEAlgorithms();


    /**
     * Returns the names of the supported encryption methods by the JWE
     * provier. These correspond to the {@code enc} JWE header parameter.
     *
     * @return The supported encryption methods, empty set if none.
     */
    Set<EncryptionMethod> supportedEncryptionMethods();
}
