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
package be.atbash.ee.security.octopus.nimbus.jwk;


import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.jupiter.api.Test;

import java.security.spec.ECParameterSpec;
import java.util.Arrays;


/**
 * Tests the EC parameter table.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class ECParameterTableTest {

    @Test
    public void testParametersAgainstBouncyCastle() {

        for (Curve crv : Arrays.asList(Curve.P_256, Curve.SECP256K1, Curve.P_384, Curve.P_521)) {

            ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec(crv.getStdName());

            ECParameterSpec expectedSpec = new ECNamedCurveSpec(curveParams.getName(),
                    curveParams.getCurve(),
                    curveParams.getG(),
                    curveParams.getN());

            // Lookup
            ECParameterSpec spec = ECParameterTable.get(crv);
            Assertions.assertThat(spec).isNotNull();
            Assertions.assertThat(spec.getCurve().getField().getFieldSize()).isEqualTo(expectedSpec.getCurve().getField().getFieldSize());
            Assertions.assertThat(spec.getCurve().getA()).isEqualTo(expectedSpec.getCurve().getA());
            Assertions.assertThat(spec.getCurve().getB()).isEqualTo(expectedSpec.getCurve().getB());
            Assertions.assertThat(spec.getGenerator().getAffineX()).isEqualTo(expectedSpec.getGenerator().getAffineX());
            Assertions.assertThat(spec.getGenerator().getAffineY()).isEqualTo(expectedSpec.getGenerator().getAffineY());
            Assertions.assertThat(spec.getOrder()).isEqualTo(expectedSpec.getOrder());
            Assertions.assertThat(spec.getCofactor()).isEqualTo(expectedSpec.getCofactor());

            // Reverse lookup
            Assertions.assertThat(ECParameterTable.get(expectedSpec)).isEqualTo(crv);
        }
    }
}
