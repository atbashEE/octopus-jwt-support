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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.jwk.EncryptedJSONJWK;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ECCurveHelper;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jwk.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.KeyUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 */

public class JwkKeyEncoderPrivatePart implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {

        if (KeyType.RSA.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeRSAKey(atbashKey, parameters);
        }
        if (KeyType.EC.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeECKey(atbashKey, parameters);
        }
        if (KeyType.OKP.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeOKPKey(atbashKey, parameters);
        }

        throw new KeyTypeException(atbashKey.getSecretKeyType().getKeyType(), "writing JWK");
    }

    private byte[] encodeRSAKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) KeyUtils.getPublicKey(atbashKey)).keyID(atbashKey.getKeyId())
                .privateKey((RSAPrivateKey) atbashKey.getKey())
                .build();

        String result;
        if (parameters.getKeyPassword() != null) {
            result = EncryptedJSONJWK.encryptedOutput(rsaKey, parameters.getKeyPassword());
        } else {
            result = rsaKey.toJSONObject().build().toString();
        }
        return result.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeECKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {
        Curve curve = ECCurveHelper.getCurve((java.security.interfaces.ECKey) atbashKey.getKey());

        ECKey ecKey = new ECKey.Builder(curve, (ECPublicKey) KeyUtils.getPublicKey(atbashKey)).keyID(atbashKey.getKeyId())
                .privateKey((ECPrivateKey) atbashKey.getKey())
                .build();

        String result;
        if (parameters.getKeyPassword() != null) {
            result = EncryptedJSONJWK.encryptedOutput(ecKey, parameters.getKeyPassword());
        } else {
            result = ecKey.toJSONObject().build().toString();
        }
        return result.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encodeOKPKey(AtbashKey atbashKey, KeyEncoderParameters parameters) {

        // TODO Check if type from BouncyCastle especially when JDK has support for it.
        BCEdDSAPrivateKey key = (BCEdDSAPrivateKey) atbashKey.getKey();

        // The next code statements are required to get access to the x and d values of the private Key.
        // BouncyCastle should have support for it!
        ASN1Primitive primitive;
        try (ASN1InputStream stream = new ASN1InputStream(key.getEncoded())) {
            try {
                primitive = stream.readObject();
            } catch (IOException e) {
                throw new AtbashUnexpectedException(e);
            }
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

        String result;
        if (parameters.getKeyPassword() != null) {
            result = EncryptedJSONJWK.encryptedOutput(jwk, parameters.getKeyPassword());
        } else {
            result = jwk.toJSONObject().build().toString();
        }
        return result.getBytes(StandardCharsets.UTF_8);
    }


}
