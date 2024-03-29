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
package be.atbash.ee.security.octopus.keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public class ValidateRemoteJWKSetURI {

    private static final Logger LOGGER = LoggerFactory.getLogger(ValidateRemoteJWKSetURI.class);

    private final List<RemoteJWKSetURIValidator> validators;

    public ValidateRemoteJWKSetURI(List<RemoteJWKSetURIValidator> validators) {
        this.validators = validators;
    }

    public boolean validate(URI jku) {
        boolean result = false;
        Optional<Boolean> isValid = validators.stream().map(v -> v.isValid(jku)).filter(r -> r).findAny();
        if (isValid.isPresent()) {
            result = true;
        }
        if (!result) {
            LOGGER.info(String.format("Following JKU '%s' is not declared as valid. Ignoring value", jku.toASCIIString()));
        }
        return result;
    }
}
