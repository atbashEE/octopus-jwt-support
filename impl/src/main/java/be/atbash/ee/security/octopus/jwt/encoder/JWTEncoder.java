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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersPlain;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.ee.security.octopus.nimbus.jose.*;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.util.JsonbUtil;
import be.atbash.util.PublicAPI;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import java.text.ParseException;

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

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    public String encode(Object data, JWTParameters parameters) {
        checkDependencies();

        String result;

        switch (parameters.getEncoding()) {
            case NONE:
                result = createJSONString(data);
                break;
            case PLAIN:
                PlainJWT plainJWT = createPlainJWT(data, (JWTParametersPlain) parameters);
                result = plainJWT.serialize();
                break;
            case JWS:
                JWSObject jwtObject = createJWTObject(data, (JWTParametersSigning) parameters);
                result = jwtObject.serialize();
                break;
            case JWE:
                JWEObject jwe = createEncryptedJWE(data, (JWTParametersEncryption) parameters);
                // Serialise to JWE compact form
                result = jwe.serialize();
                break;
            default:
                throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", parameters.getEncoding()));
        }
        return result;

    }

    /**
     * Serialize to the Flattened JWS JSON Serialization.
     *
     * @param data       The content that must be 'wrapped' into JWS/JWE.
     * @param parameters Determines the parameters for the creation.
     * @return the Flattened JWS JSON Serialization.
     */
    public JsonObject encodeAsJson(Object data, JWTParameters parameters) {
        checkDependencies();

        JsonObject result;

        switch (parameters.getEncoding()) {
            case NONE:
                throw new UnsupportedOperationException("Encoding NONE is not supported to JWT JSON Serialization format");
            case PLAIN:
                PlainJWT plainJWT = createPlainJWT(data, (JWTParametersPlain) parameters);
                result = plainJWT.serializeToJson();
                break;
            case JWS:
                JWSObject jwtObject = createJWTObject(data, (JWTParametersSigning) parameters);
                result = jwtObject.serializeToJson();
                break;
            case JWE:
                JWEObject encryptedJWE = createEncryptedJWE(data, (JWTParametersEncryption) parameters);
                result = encryptedJWE.serializeToJson();
                break;
            default:
                throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", parameters.getEncoding()));
        }
        return result;

    }

    private PlainJWT createPlainJWT(Object data, JWTParametersPlain parameters) {
        PlainHeader header = new PlainHeader.Builder().parameters(parameters.getHeaderValues()).build();

        PlainJWT plainJWT;
        if (data instanceof JWTClaimsSet) {
            plainJWT = new PlainJWT(header, (JWTClaimsSet) data);
        } else {
            String payload = createJSONString(data);
            try {
                plainJWT = new PlainJWT(header, JSONObjectUtils.parse(payload, Header.MAX_HEADER_STRING_LENGTH));
            } catch (ParseException e) {
                throw new AtbashUnexpectedException(String.format("JSON string can't be parsed which is unexpected %n%s%n%s", payload, e.getMessage()));
            }
        }

        return plainJWT;
    }

    private JWEObject createEncryptedJWE(Object data, JWTParametersEncryption parameters) {

        JWEAlgorithm jweAlgorithm = parameters.getJweAlgorithm();
        if (jweAlgorithm == null) {
            jweAlgorithm = defineDefaultJWEAlgorithm(parameters);
        }

        if (jweAlgorithm == null) {
            throw new KeyTypeException(parameters.getKeyType(), "JWE creation");
        }
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(jweAlgorithm, EncryptionMethod.A256GCM)
                        .keyID(parameters.getKeyID())
                        .parameters(parameters.getHeaderValues())
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(createJWTObject(data, parameters.getParametersSigning()).serialize()));

        // Perform encryption
        jweObject.encrypt(encryptionFactory.createEncryptor(parameters));

        return jweObject;
    }

    private JWEAlgorithm defineDefaultJWEAlgorithm(JWTParametersEncryption parameters) {
        JWEAlgorithm result = null;
        if (parameters.getKeyType() == KeyType.RSA) {
            result = jwtSupportConfiguration.getDefaultJWEAlgorithmRSA();
        }
        if (parameters.getKeyType() == KeyType.EC) {
            result = jwtSupportConfiguration.getDefaultJWEAlgorithmEC();
        }
        if (parameters.getKeyType() == KeyType.OCT) {

            result = jwtSupportConfiguration.getDefaultJWEAlgorithmOCT();
        }
        return result;
    }

    private JWSObject createJWTObject(Object data, JWTParametersSigning parameters) {
        JWSObject jwsObject;

        JWSHeader header = new JWSHeader.Builder(signerFactory.defineJWSAlgorithm(parameters))
                .type(JOSEObjectType.JWT)
                .keyID(parameters.getKeyID())
                .parameters(parameters.getHeaderValues())
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

        Jsonb jsonb = JsonbUtil.getJsonb();
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
