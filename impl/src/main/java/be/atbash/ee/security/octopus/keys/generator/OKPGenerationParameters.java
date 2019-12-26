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
package be.atbash.ee.security.octopus.keys.generator;

import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.PublicAPI;

@PublicAPI
public class OKPGenerationParameters extends GenerationParameters {

// OCTKEY https://tools.ietf.org/html/rfc8037
        /*
        Octet key pair (OKP)
This key type is used by the EdDSA algorithms.

signature with curves Ed25519 and Ed448
encryption with curves X25519 nd X448
At the moment, only Ed25519 and X25519 curves are supported.

Public keys must contain crv (curve) and x values. Private keys will also contain a value d.

         */
    // ED25519 has a fixed key Size

    private OKPGenerationParameters(OKPGenerationParametersBuilder builder) {

        super(builder, KeyType.OKP);
    }

    public static class OKPGenerationParametersBuilder extends GenerationParametersBuilders<OKPGenerationParametersBuilder> {

        public OKPGenerationParameters build() {
            applyDefaults();
            return new OKPGenerationParameters(this);
        }


    }
}
