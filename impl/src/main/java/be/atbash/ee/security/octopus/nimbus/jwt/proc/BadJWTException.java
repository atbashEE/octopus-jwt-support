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
 * Bad JSON Web Token (JWT) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-29
 */
public class BadJWTException extends BadJOSEException {
// also used in oauth2-oidc-sdk

    /**
     * Creates a new bad JWT exception.
     *
     * @param message The exception message.
     */
    public BadJWTException(String message) {

        super(message);
    }


    /**
     * Creates a new bad JWT exception.
     *
     * @param message The exception message.
     * @param cause   The exception cause.
     */
    public BadJWTException(String message, Throwable cause) {

        super(message, cause);
    }
}
