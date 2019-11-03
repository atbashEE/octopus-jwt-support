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
package be.atbash.ee.security.octopus.nimbus.jose.proc;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEProvider;

import java.security.Key;


/**
 * JSON Web Encryption (JWE) decrypter factory.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-11-16
 */
public interface JWEDecrypterFactory extends JWEProvider {


    /**
     * Creates a new JWE decrypter for the specified header and key.
     *
     * @param header The JWE header. Not {@code null}.
     * @param key    The key intended to verify the JWS message. Not
     *               {@code null}.
     * @return The JWE decrypter.
     * @throws JOSEException If the JWE algorithm / encryption method is
     *                       not supported or the key type or length
     *                       doesn't match expected for the JWE algorithm.
     */
    JWEDecrypter createJWEDecrypter(JWEHeader header, Key key)
            throws JOSEException;
}
