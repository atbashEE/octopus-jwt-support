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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.UnsupportedKeyType;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ECCurveHelper;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.ECKey;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.x9.X9ECParameters;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static be.atbash.ee.security.octopus.nimbus.jwk.ECKey.SUPPORTED_CURVES;


/**
 *
 */

public class JwkKeyEncoderPublicPart implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {

        if (KeyType.RSA.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeRSAKey(atbashKey);
        }

        if (KeyType.EC.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeECKey(atbashKey);
        }
        throw new UnsupportedKeyType(atbashKey.getSecretKeyType().getKeyType(), "writing JWK");
    }

    private byte[] encodeRSAKey(AtbashKey atbashKey) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) atbashKey.getKey()).keyID(atbashKey.getKeyId())
                .build();

        return rsaKey.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeECKey(AtbashKey atbashKey) {
        Curve curve = ECCurveHelper.getCurve((java.security.interfaces.ECKey) atbashKey.getKey());
        if (curve == null) {
            throw new AtbashUnexpectedException(String.format("Unable to determine EC Curve of %s", atbashKey.getKeyId()));
        }

        ECKey ecKey = new ECKey.Builder(curve, (ECPublicKey) atbashKey.getKey()).keyID(atbashKey.getKeyId())
                .build();

        return ecKey.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private Curve deriveCurve(org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec) throws GeneralSecurityException {

        for (Curve supportedCurve : SUPPORTED_CURVES) {

            String name = supportedCurve.getName();

            X9ECParameters params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);

            if (params != null) {
                if (params.getN().equals(ecParameterSpec.getN())
                        && params.getH().equals(ecParameterSpec.getH())
                        && params.getCurve().equals(ecParameterSpec.getCurve())
                        && params.getG().equals(ecParameterSpec.getG())) {
                    return supportedCurve;
                }
            }
        }

        throw new GeneralSecurityException("Could not find name for curve");
    }

}
