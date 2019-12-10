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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;


import be.atbash.ee.security.octopus.nimbus.jose.proc.BadJOSEException;

/**
 * Bad JSON Web Encryption (JWE) exception. Used to indicate a JWE-protected
 * object that couldn't be successfully decrypted or its integrity has been
 * compromised.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-11
 */
public class BadJWEException extends BadJOSEException {


    /**
     * Creates a new bad JWE exception.
     *
     * @param message The exception message.
     */
    public BadJWEException(String message) {

        super(message);
    }


    /**
     * Creates a new bad JWE exception.
     *
     * @param message The exception message.
     * @param cause   The exception cause.
     */
    public BadJWEException(String message, Throwable cause) {

        super(message, cause);
    }
}
