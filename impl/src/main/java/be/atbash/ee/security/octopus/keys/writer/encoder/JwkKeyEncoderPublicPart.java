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
import be.atbash.ee.security.octopus.nimbus.jwk.*;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;


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
        if (KeyType.OKP.equals(atbashKey.getSecretKeyType().getKeyType())) {
            return encodeOKPKey(atbashKey);
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

    private byte[] encodeOKPKey(AtbashKey atbashKey) {

        // The next code statements are required to get access to the x value of the public Key.
        // BouncyCastle should have support for it!

        ASN1InputStream stream = new ASN1InputStream(atbashKey.getKey().getEncoded());
        ASN1Primitive primitive = null;
        try {
            primitive = stream.readObject();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        //[[1.3.101.112], #032100238DBA14FF77991890E136DAF5B0844C1AB096E513A361F0F26FCEDCD7E9E7DA]
        DLSequence sequence = (DLSequence) primitive;

        ASN1Encodable x1 = sequence.getObjectAt(1);
        DERBitString publicBytes = (DERBitString) x1;

        OctetKeyPair jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URLValue.encode(publicBytes.getOctets()))
                .keyID(atbashKey.getKeyId())
                .build();

        return jwk.toJSONObject().build().toString().getBytes(StandardCharsets.UTF_8);
    }

}
