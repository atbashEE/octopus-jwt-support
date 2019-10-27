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
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.ECKey;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.RSAKey;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;

import static be.atbash.ee.security.octopus.nimbus.jose.jwk.ECKey.SUPPORTED_CURVES;


/**
 *
 */

public class JwkKeyEncoderPublicPart implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {

        if (KeyType.RSA.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeRSAKey(atbashKey);
        }

        if (KeyType.EC.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeECKey(atbashKey);
        }
        // FIXME Support for OCT.
        throw new UnsupportedKeyType(atbashKey.getSecretKeyType().getKeyType(), "writing JWK");
    }

    private byte[] encodeRSAKey(AtbashKey atbashKey) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) atbashKey.getKey()).keyID(atbashKey.getKeyId())
                .build();

        return rsaKey.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeECKey(AtbashKey atbashKey) {
        Curve curve;
        try {
            curve = deriveCurve((PublicKey) atbashKey.getKey());
        } catch (GeneralSecurityException e) {
            throw new AtbashUnexpectedException(e);
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

    private Curve deriveCurve(PublicKey publicKey) throws GeneralSecurityException {
        if (publicKey instanceof java.security.interfaces.ECPublicKey) {
            final java.security.interfaces.ECPublicKey pk = (java.security.interfaces.ECPublicKey) publicKey;
            final ECParameterSpec params = pk.getParams();
            return deriveCurve(EC5Util.convertSpec(params, false));
        } else if (publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
            final org.bouncycastle.jce.interfaces.ECPublicKey pk = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
            return deriveCurve(pk.getParameters());
        } else
            throw new IllegalArgumentException("Can only be used with instances of ECPublicKey (either jce or bc implementation)");
    }


}
