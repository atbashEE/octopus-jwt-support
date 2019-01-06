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
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static com.nimbusds.jose.jwk.ECKey.SUPPORTED_CURVES;

/**
 *
 */

public class JwkKeyEncoderPrivatePart implements KeyEncoder {

    public JwkKeyEncoderPrivatePart() {
        Security.addProvider(new BouncyCastleProvider());
    }

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
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) getPublicKey(atbashKey.getKey())).keyID(atbashKey.getKeyId())
                .privateKey((RSAPrivateKey) atbashKey.getKey())
                .build();

        return rsaKey.toJSONObject().toJSONString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeECKey(AtbashKey atbashKey) {
        Curve curve;
        try {
            curve = deriveCurve((PrivateKey) atbashKey.getKey());
        } catch (GeneralSecurityException e) {
            throw new AtbashUnexpectedException(e);
        }
        ECKey jwk = new ECKey.Builder(curve, (ECPublicKey) getPublicKey(atbashKey.getKey(), curve)).keyID(atbashKey.getKeyId())
                .privateKey((ECPrivateKey) atbashKey.getKey())
                .build();

        return jwk.toJSONObject().toJSONString().getBytes(StandardCharsets.UTF_8);
    }

    // Duplicated
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

    private Curve deriveCurve(PrivateKey privateKey) throws GeneralSecurityException {
        if (privateKey instanceof java.security.interfaces.ECPrivateKey) {
            java.security.interfaces.ECPrivateKey pk = (java.security.interfaces.ECPrivateKey) privateKey;
            ECParameterSpec params = pk.getParams();
            return deriveCurve(EC5Util.convertSpec(params, false));
        } else if (privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey) {
            org.bouncycastle.jce.interfaces.ECPrivateKey pk = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
            return deriveCurve(pk.getParameters());
        } else
            throw new IllegalArgumentException("Can only be used with instances of ECPrivateKey (either jce or bc implementation)");
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
