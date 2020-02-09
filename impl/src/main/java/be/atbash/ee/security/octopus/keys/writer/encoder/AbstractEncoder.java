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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ECCurveHelper;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public abstract class AbstractEncoder {

    protected PublicKey getPublicKey(AtbashKey atbashKey) {
        Key key = atbashKey.getKey();
        // FIXME Move this to a general helper utility class?
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) key;

            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            try {

                KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProviderSingleton.getInstance());

                return keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {
                throw new AtbashUnexpectedException(e);
            }
        }
        if (key instanceof BCECPrivateKey) {
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) key;
            ECNamedCurveParameterSpec parameters = (ECNamedCurveParameterSpec) bcecPrivateKey.getParameters();
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(parameters.getName());

                ECPoint Q = ecSpec.getG().multiply(bcecPrivateKey.getD());

                ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
                return keyFactory.generatePublic(pubSpec);
            } catch (Exception e) {
                throw new AtbashUnexpectedException(e);
            }

        }
        throw new UnsupportedOperationException("TODO");
    }
}
