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
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static be.atbash.ee.security.octopus.nimbus.jwk.ECKey.SUPPORTED_CURVES;

/**
 *
 */

public class JwkKeyEncoderPrivatePart implements KeyEncoder {

    public JwkKeyEncoderPrivatePart() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {

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
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) getPublicKey(atbashKey.getKey())).keyID(atbashKey.getKeyId())
                .privateKey((RSAPrivateKey) atbashKey.getKey())
                .build();

        return rsaKey.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeECKey(AtbashKey atbashKey) {
        Curve curve = deriveCurve(atbashKey);

        ECKey jwk = new ECKey.Builder(curve, (ECPublicKey) getPublicKey(atbashKey.getKey(), curve)).keyID(atbashKey.getKeyId())
                .privateKey((ECPrivateKey) atbashKey.getKey())
                .build();

        return jwk.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

    private Curve deriveCurve(AtbashKey atbashKey) {

        Curve curve = ECCurveHelper.getCurve((java.security.interfaces.ECKey) atbashKey.getKey());
        if (curve == null) {
            throw new AtbashUnexpectedException(String.format("Unable to determine EC Curve of %s", atbashKey.getKeyId()));
        }
        return curve;

    }

    private PublicKey getPublicKey(Key key) {
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) key;

            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                return keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {
                throw new AtbashUnexpectedException(e);
            }
        }
        throw new UnsupportedOperationException("TODO");

    }

    private PublicKey getPublicKey(Key key, Curve curve) {

        if (key instanceof ECPrivateKey) {
            // TODO Optimize
            if (key instanceof org.bouncycastle.jce.interfaces.ECPrivateKey) {
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
                    org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getStdName());

                    ECPoint q = ecSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) key).getD());

                    ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, ecSpec);
                    return keyFactory.generatePublic(pubSpec);
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }
        throw new UnsupportedOperationException("TODO");

    }
}
