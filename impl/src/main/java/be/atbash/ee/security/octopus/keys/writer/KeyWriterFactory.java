/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keys.writer;

import be.atbash.ee.security.octopus.config.PemKeyEncryption;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.writer.encoder.*;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class KeyWriterFactory {

    private Map<String, KeyEncoder> notEncryptedEncoder;

    private PemKeyEncoderPublicPart publicPartEncoder;

    private PemKeyEncoderPrivatePartPKCS1 privatePartPKCS1Encoder;
    private PemKeyEncoderPrivatePartPKCS8 privatePartPKCS8Encoder;

    private JwkKeyEncoderPrivatePart privatePartJwkEncoder;
    private JwkKeyEncoderPublicPart publicPartJwkEncoder;

    private KeyStoreEncoder keyStoreEncoder;

    @PostConstruct
    public void init() {
        notEncryptedEncoder = new HashMap<>();
        notEncryptedEncoder.put("RSA", new PemKeyEncoderPrivatePartNotEncrypted("RSA"));
        notEncryptedEncoder.put("EC", new PemKeyEncoderPrivatePartNotEncrypted("EC"));
        publicPartEncoder = new PemKeyEncoderPublicPart();

        privatePartPKCS1Encoder = new PemKeyEncoderPrivatePartPKCS1();
        privatePartPKCS8Encoder = new PemKeyEncoderPrivatePartPKCS8();

        privatePartJwkEncoder = new JwkKeyEncoderPrivatePart();
        publicPartJwkEncoder = new JwkKeyEncoderPublicPart();

        keyStoreEncoder = new KeyStoreEncoder();
    }

    public byte[] writeKeyAsKeyStore(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        // TODO Additional branching needed?
        return keyStoreEncoder.encodeKey(atbashKey, parameters);
    }

    public byte[] writeKeyAsJWK(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
            return privatePartJwkEncoder.encodeKey(atbashKey, parameters);
        } else {
            return publicPartJwkEncoder.encodeKey(atbashKey, parameters);
        }
    }

    public byte[] writeKeyAsPEM(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        byte[] result;
        if (atbashKey.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PRIVATE) {
            PemKeyEncryption pemKeyEncryption = parameters.getValue(PemKeyEncryption.class);
            switch (pemKeyEncryption) {
                case NONE:
                    result = notEncryptedEncoder.get(atbashKey.getSecretKeyType().getKeyType().getValue())
                            .encodeKey(atbashKey, parameters);
                    break;
                case PKCS8:
                    result = privatePartPKCS8Encoder.encodeKey(atbashKey, parameters);
                    break;
                case PKCS1:
                    result = privatePartPKCS1Encoder.encodeKey(atbashKey, parameters);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unsupported value for PemKeyEncryption : %s", pemKeyEncryption));
            }

        } else {
            result = publicPartEncoder.encodeKey(atbashKey, parameters);
        }
        return result;
    }

    public byte[] writeKeyAsJWKSet(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        byte[] result;
        String jwkJSON = new String(writeKeyAsJWK(atbashKey, parameters));
        try {
            JWK jwk = JWK.parse(jwkJSON);
            List<JWK> jwks = new ArrayList<>();
            jwks.add(jwk);
            jwks.addAll(parameters.getJwkSet().getKeys());

            JWKSet jwkSet = new JWKSet(jwks);
            result = jwkSet.toJSONObject(false).toJSONString().getBytes(StandardCharsets.UTF_8);
        } catch (ParseException e) {
            // This can never happen as the String is a JSON representation of an actual JWK instance.
            throw new AtbashUnexpectedException(e);
        }
        return result;

    }
}
