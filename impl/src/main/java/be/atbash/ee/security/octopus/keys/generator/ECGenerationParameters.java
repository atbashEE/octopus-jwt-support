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

import be.atbash.ee.security.octopus.nimbus.jose.jwk.KeyType;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

@PublicAPI
public class ECGenerationParameters extends GenerationParameters {

    private String curveName;

    private ECGenerationParameters(ECGenerationParametersBuilder builder) {

        super(builder, KeyType.EC);
        if (StringUtils.isEmpty(builder.curveName)) {
            throw new KeyGenerationParameterException("EC Curve name is required");
        }
        curveName = builder.curveName;
    }

    public String getCurveName() {
        return curveName;
    }

    public static class ECGenerationParametersBuilder extends GenerationParametersBuilders<ECGenerationParametersBuilder> {

        private String curveName;

        public ECGenerationParameters build() {
            applyDefaults();
            return new ECGenerationParameters(this);
        }

        public ECGenerationParametersBuilder withCurveName(String curveName) {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
            if (ecSpec == null) {
                throw new KeyGenerationParameterException(String.format("EC Curve name '%s' unknown", curveName));
            }
            this.curveName = curveName;
            return this;
        }
    }
}
