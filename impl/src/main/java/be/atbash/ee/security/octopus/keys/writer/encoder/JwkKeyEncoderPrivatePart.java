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
import be.atbash.ee.security.octopus.nimbus.jwk.ECKey;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwk.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

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
        if (KeyType.OKP.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeOKPKey(atbashKey);
        }

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

    private byte[] encodeOKPKey(AtbashKey atbashKey) {

        // TODO Check if type from BouncyCastle especially when JKD has support for it.
        BCEdDSAPrivateKey key = (BCEdDSAPrivateKey) atbashKey.getKey();

        // The next code statements are required to get access to the x and d values of the private Key.
        // BouncyCastle should have support for it!
        ASN1InputStream stream = new ASN1InputStream(key.getEncoded());
        ASN1Primitive primitive;
        try {
            primitive = stream.readObject();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        // [1, [1.3.101.112], #0420f615acda8498cfc96c45c00f80e2438aa490f9e8b1201320aba968d7e750095d, [1]#00f2c6678839670f1abaed87171ac938122cd4c62e4c6d24c7620f63da893ab682]
        DLSequence sequence = (DLSequence) primitive;

        ASN1Encodable item1 = sequence.getObjectAt(2);
        DEROctetString privateBytes = (DEROctetString) item1;

        byte[] dBytes = new byte[Ed25519.SECRET_KEY_SIZE];
        System.arraycopy(privateBytes.getOctets(), 2, dBytes, 0, Ed25519.SECRET_KEY_SIZE);

        ASN1Encodable item2 = sequence.getObjectAt(3);
        DLTaggedObject publicPart = (DLTaggedObject) item2;
        DEROctetString publicBytes = (DEROctetString) publicPart.getObject();

        byte[] xBytes = new byte[Ed25519.SECRET_KEY_SIZE];
        System.arraycopy(publicBytes.getOctets(), 1, xBytes, 0, Ed25519.SECRET_KEY_SIZE);

        OctetKeyPair jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URLValue.encode(xBytes))
                .keyID(atbashKey.getKeyId())
                .d(Base64URLValue.encode(dBytes))
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
