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
package be.atbash.ee.security.octopus.keys.generator;

import be.atbash.ee.security.octopus.config.JCASupportConfiguration;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@PublicAPI
@ApplicationScoped
public class KeyGenerator {

    public List<AtbashKey> generateKeys(GenerationParameters parameters) {
        List<AtbashKey> result = null;
        if (KeyType.RSA.equals(parameters.getKeyType())) {
            result = generateRSAKeys((RSAGenerationParameters) parameters);
        }
        if (KeyType.EC.equals(parameters.getKeyType())) {
            result = generateECKeys((ECGenerationParameters) parameters);
        }
        if (KeyType.OCT.equals(parameters.getKeyType())) {
            result = generateOctKey((OCTGenerationParameters) parameters);
        }
        if (KeyType.OKP.equals(parameters.getKeyType())) {
            result = generateOKPKeys((OKPGenerationParameters) parameters);
        }
        if (DHGenerationParameters.DH.equals(parameters.getKeyType())) {
            result = generateDHKeys((DHGenerationParameters) parameters);
        }
        if (result == null) {
            throw new KeyTypeException(parameters.getKeyType(), "Key generation");
        }
        return result;
    }

    private List<AtbashKey> generateRSAKeys(RSAGenerationParameters generationParameters) {
        try {

            KeyPairGenerator generator = KeyPairGenerator.getInstance(JWKIdentifiers.RSA_KEY_TYPE, BouncyCastleProviderSingleton.getInstance());

            generator.initialize(generationParameters.getKeySize(), JCASupportConfiguration.getInstance().getSecureRandom());
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

            List<AtbashKey> result = new ArrayList<>();
            result.add(new AtbashKey(generationParameters.getKid(), pub));
            result.add(new AtbashKey(generationParameters.getKid(), priv));
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    private List<AtbashKey> generateDHKeys(DHGenerationParameters generationParameters) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            if (generationParameters.getParameterSpec() != null) {
                generator.initialize(generationParameters.getParameterSpec());
            } else {
                generator.initialize(generationParameters.getKeySize(), JCASupportConfiguration.getInstance().getSecureRandom());

            }
            KeyPair kp = generator.generateKeyPair();

            DHPublicKey pub = (DHPublicKey) kp.getPublic();
            DHPrivateKey priv = (DHPrivateKey) kp.getPrivate();

            List<AtbashKey> result = new ArrayList<>();
            result.add(new AtbashKey(generationParameters.getKid(), pub));
            result.add(new AtbashKey(generationParameters.getKid(), priv));
            return result;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    private List<AtbashKey> generateECKeys(ECGenerationParameters generationParameters) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(generationParameters.getCurveName());

            KeyPairGenerator generator = KeyPairGenerator.getInstance(JWKIdentifiers.ELLIPTIC_CURVE_KEY_TYPE, BouncyCastleProviderSingleton.getInstance());

            generator.initialize(ecSpec, JCASupportConfiguration.getInstance().getSecureRandom());
            KeyPair kp = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

            List<AtbashKey> result = new ArrayList<>();
            result.add(new AtbashKey(generationParameters.getKid(), pub));
            result.add(new AtbashKey(generationParameters.getKid(), priv));
            return result;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    private List<AtbashKey> generateOKPKeys(OKPGenerationParameters generationParameters) {
        try {
            // FIXME support for other algorithms
            KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProviderSingleton.getInstance());
            g.initialize(256, JCASupportConfiguration.getInstance().getSecureRandom());
            KeyPair kp = g.generateKeyPair();


            List<AtbashKey> result = new ArrayList<>();
            result.add(new AtbashKey(generationParameters.getKid(), kp.getPublic()));
            result.add(new AtbashKey(generationParameters.getKid(), kp.getPrivate()));
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    private List<AtbashKey> generateOctKey(OCTGenerationParameters generationParameters) {
        byte[] bytes = new byte[generationParameters.getKeySize() / 8];
        JCASupportConfiguration.getInstance().getSecureRandom().nextBytes(bytes);

        SecretKeySpec secretKey = new SecretKeySpec(bytes, "AES");

        List<AtbashKey> result = new ArrayList<>();
        result.add(new AtbashKey(generationParameters.getKid(), secretKey));

        return result;
    }

}
