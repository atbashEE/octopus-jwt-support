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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.UnsupportedKeyType;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.ee.security.octopus.jwt.serializer.spi.SerializerProvider;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class JWTEncoder {

    @Inject
    private JWTSignerFactory signerFactory;

    @Inject
    private JWEEncryptionFactory encryptionFactory;

    public String encode(Object data, JWTParameters parameters) {
        checkDependencies();

        String result;

        try {
            switch (parameters.getEncoding()) {
                case NONE:
                    result = createJSONString(data);
                    break;
                case JWS:
                    result = createSignedJWT(data, (JWTParametersSigning) parameters);
                    break;
                case JWE:
                    result = createEncryptedJWE(data, (JWTParametersEncryption) parameters);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", parameters.getEncoding()));
            }
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;

    }

    private String createEncryptedJWE(Object data, JWTParametersEncryption parameters) throws JOSEException {

        JWEAlgorithm jweAlgorithm = null;
        if (parameters.getKeyType() == KeyType.RSA) {
            jweAlgorithm = JWEAlgorithm.RSA_OAEP_256;  // TODO Configurable, SPI ?
        }
        if (parameters.getKeyType() == KeyType.EC) {
            jweAlgorithm = JWEAlgorithm.ECDH_ES_A256KW;// TODO Configurable, SPI ?
        }
        if (parameters.getKeyType() == KeyType.OCT) {
            jweAlgorithm = JWEAlgorithm.A256KW;// TODO Configurable, SPI ?
        }

        if (jweAlgorithm == null) {
            throw new UnsupportedKeyType(parameters.getKeyType(), "JWE creation");
        }
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(jweAlgorithm, EncryptionMethod.A256GCM)
                        .keyID(parameters.getKeyID())
                        .customParams(parameters.getHeaderValues())
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(createSignedJWT(data, parameters.getParametersSigning())));

        // Perform encryption
        jweObject.encrypt(encryptionFactory.createEncryptor(parameters));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private String createSignedJWT(Object data, JWTParametersSigning parameters) throws JOSEException {
        JWSObject jwsObject = createJWTObject(data, parameters);
        return jwsObject.serialize();
    }

    private JWSObject createJWTObject(Object data, JWTParametersSigning parameters) throws JOSEException {
        JWSObject jwsObject;

        JWSHeader header = new JWSHeader.Builder(signerFactory.defineJWSAlgorithm(parameters))
                .type(JOSEObjectType.JWT)
                .keyID(parameters.getKeyID())
                .customParams(parameters.getHeaderValues())
                .build();

        if (data instanceof JWTClaimsSet) {
            JsonObject jsonObject = ((JWTClaimsSet) data).toJSONObject();
            jwsObject = new JWSObject(header, new Payload(jsonObject));
        } else {
            String payload = createJSONString(data);

            jwsObject = new JWSObject(header, new Payload(payload));
        }

        // Apply the Signing protection
        JWSSigner signer = signerFactory.createSigner(parameters);

        jwsObject.sign(signer);

        return jwsObject;
    }

    private String createJSONString(Object data) {
        JsonbConfig config = new JsonbConfig();

        config.withSerializers(SerializerProvider.getInstance().getSerializers());
        Jsonb jsonb = JsonbBuilder.create(config);
        return jsonb.toJson(data);
    }

    private void checkDependencies() {
        // We have CDI injected dependencies, but in a Java SE environment it is possible that they are empty.
        if (signerFactory == null) {
            signerFactory = new JWTSignerFactory();
        }

        if (encryptionFactory == null) {
            encryptionFactory = new JWEEncryptionFactory();
        }
    }

}
