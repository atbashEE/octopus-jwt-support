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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;

/**
 *
 */

public final class ECCurveHelper {

    private ECCurveHelper() {

    }

    public static Curve getCurve(ECKey ecKey) {
        ECParameterSpec params = ecKey.getParams();
        if (!(params instanceof ECNamedCurveSpec)) {
            return null;
        }

        ECNamedCurveSpec ecPrivateKeySpec = (ECNamedCurveSpec) params;
        String namedCurve = ecPrivateKeySpec.getName();

        return Curve.parse(namedCurve);
    }

}
