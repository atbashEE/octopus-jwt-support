/*
 * Copyright 2017-2020 Rudy De Busscher (https://www.atbash.be)
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


import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.security.spec.ECParameterSpec;


/**
 * Elliptic curve parameter table.
 *
 * <p>Supports the following standard EC JWK curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256}
 *     <li>{@link Curve#P_256K}
 *     <li>{@link Curve#P_384}
 *     <li>{@link Curve#P_521}
 * </ul>
 *
 * Based on code by Vladimir Dzhuvinov and Aleksei Doroganov
 */
final class ECParameterTable {


    /**
     * The parameter spec for a
     * {@link Curve#P_256} curve.
     */
    private static final ECNamedCurveSpec P_256_SPEC;


    /**
     * The parameter spec for a
     * {@link Curve#P_256K} curve.
     */
    private static final ECNamedCurveSpec P_256K_SPEC;


    /**
     * The parameter spec for a
     * {@link Curve#P_384} curve.
     */
    private static final ECNamedCurveSpec P_384_SPEC;


    /**
     * The parameter spec for a
     * {@link Curve#P_521} curve.
     */
    private static final ECNamedCurveSpec P_521_SPEC;

    static {

        P_256_SPEC = createNamedCurveSpec(Curve.P_256);
        P_256K_SPEC = createNamedCurveSpec(Curve.P_256K);
        P_384_SPEC = createNamedCurveSpec(Curve.P_384);
        P_521_SPEC = createNamedCurveSpec(Curve.P_521);
    }

    static ECNamedCurveSpec createNamedCurveSpec(Curve curve) {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curve.getStdName());
        return new ECNamedCurveSpec(parameterSpec.getName(), parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN());
    }

    /**
     * Gets the parameter specification for the specified elliptic curve.
     *
     * @param curve The JWK elliptic curve. May be {@code null}.
     * @return The EC parameter spec, {@code null} if it cannot be
     * determined.
     */
    public static ECParameterSpec get(Curve curve) {

        if (Curve.P_256.equals(curve)) {
            return P_256_SPEC;
        } else if (Curve.P_256K.equals(curve)) {
            return P_256K_SPEC;
        } else if (Curve.P_384.equals(curve)) {
            return P_384_SPEC;
        } else if (Curve.P_521.equals(curve)) {
            return P_521_SPEC;
        } else {
            return null;
        }
    }


    /**
     * Gets the JWK elliptic curve for the specified parameter
     * specification.
     *
     * @param spec The EC parameter spec. May be {@code null}.
     * @return The JWK elliptic curve, {@code null} if it cannot be
     * determined.
     */
    public static Curve get(ECParameterSpec spec) {

        if (spec == null) {
            return null;
        }

        if (spec.getCurve().getField().getFieldSize() == P_256_SPEC.getCurve().getField().getFieldSize() &&
                spec.getCurve().getA().equals(P_256_SPEC.getCurve().getA()) &&
                spec.getCurve().getB().equals(P_256_SPEC.getCurve().getB()) &&
                spec.getGenerator().getAffineX().equals(P_256_SPEC.getGenerator().getAffineX()) &&
                spec.getGenerator().getAffineY().equals(P_256_SPEC.getGenerator().getAffineY()) &&
                spec.getOrder().equals(P_256_SPEC.getOrder()) &&
                spec.getCofactor() == P_256_SPEC.getCofactor()) {

            return Curve.P_256;

        } else if (spec.getCurve().getField().getFieldSize() == P_256K_SPEC.getCurve().getField().getFieldSize() &&
                spec.getCurve().getA().equals(P_256K_SPEC.getCurve().getA()) &&
                spec.getCurve().getB().equals(P_256K_SPEC.getCurve().getB()) &&
                spec.getGenerator().getAffineX().equals(P_256K_SPEC.getGenerator().getAffineX()) &&
                spec.getGenerator().getAffineY().equals(P_256K_SPEC.getGenerator().getAffineY()) &&
                spec.getOrder().equals(P_256K_SPEC.getOrder()) &&
                spec.getCofactor() == P_256K_SPEC.getCofactor()) {

            return Curve.P_256K;

        } else if (spec.getCurve().getField().getFieldSize() == P_384_SPEC.getCurve().getField().getFieldSize() &&
                spec.getCurve().getA().equals(P_384_SPEC.getCurve().getA()) &&
                spec.getCurve().getB().equals(P_384_SPEC.getCurve().getB()) &&
                spec.getGenerator().getAffineX().equals(P_384_SPEC.getGenerator().getAffineX()) &&
                spec.getGenerator().getAffineY().equals(P_384_SPEC.getGenerator().getAffineY()) &&
                spec.getOrder().equals(P_384_SPEC.getOrder()) &&
                spec.getCofactor() == P_384_SPEC.getCofactor()) {

            return Curve.P_384;

        } else if (spec.getCurve().getField().getFieldSize() == P_521_SPEC.getCurve().getField().getFieldSize() &&
                spec.getCurve().getA().equals(P_521_SPEC.getCurve().getA()) &&
                spec.getCurve().getB().equals(P_521_SPEC.getCurve().getB()) &&
                spec.getGenerator().getAffineX().equals(P_521_SPEC.getGenerator().getAffineX()) &&
                spec.getGenerator().getAffineY().equals(P_521_SPEC.getGenerator().getAffineY()) &&
                spec.getOrder().equals(P_521_SPEC.getOrder()) &&
                spec.getCofactor() == P_521_SPEC.getCofactor()) {

            return Curve.P_521;

        } else {
            return null;
        }
    }


    /**
     * Prevents public instantiation.
     */
    private ECParameterTable() {

    }
}
