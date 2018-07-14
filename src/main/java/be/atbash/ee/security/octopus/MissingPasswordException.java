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
package be.atbash.ee.security.octopus;

import be.atbash.util.exception.AtbashException;

/**
 *
 */

public class MissingPasswordException extends AtbashException {

    public MissingPasswordException(ObjectType objectType) {
        super(defineMessage(objectType, null));
    }

    public MissingPasswordException(ObjectType objectType, String path) {
        super(defineMessage(objectType, path));
    }

    private static String defineMessage(ObjectType objectType, String path) {
        switch (objectType) {

            case STORE:
                return String.format("Password required for opening key store %s", path);
            case ENCRYPTION:
                return "Password required for encryption/decryption";
        }
        throw new UnsupportedOperationException(String.format("Unknown value for ObjectType %s", objectType));
    }

    public enum ObjectType {
        STORE, ENCRYPTION
    }
}
