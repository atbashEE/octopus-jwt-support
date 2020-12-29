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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersPlain;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.PlainHeader;
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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.json.bind.Jsonb;
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
                result = createPlainJWT(data, (JWTParametersPlain) parameters);
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
        return result;

    }

    private String createPlainJWT(Object data, JWTParametersPlain parameters) {
        PlainHeader header = new PlainHeader.Builder().parameters(parameters.getHeaderValues()).build();

        PlainJWT plainJWT;
        if (data instanceof JWTClaimsSet) {
            plainJWT = new PlainJWT(header, (JWTClaimsSet) data);
        } else {
            String payload = createJSONString(data);
            try {
                plainJWT = new PlainJWT(header, JSONObjectUtils.parse(payload));
            } catch (ParseException e) {
                throw new AtbashUnexpectedException(String.format("JSON string can't be parsed which is unexpected \n%s\n%s", payload, e.getMessage()));
            }
        }

        return plainJWT.serialize();
    }

    private String createEncryptedJWE(Object data, JWTParametersEncryption parameters) {

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
                new Payload(createSignedJWT(data, parameters.getParametersSigning())));

        // Perform encryption
        jweObject.encrypt(encryptionFactory.createEncryptor(parameters));

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private JWEAlgorithm defineDefaultJWEAlgorithm(JWTParametersEncryption parameters) {
        JWEAlgorithm result = null;
        if (parameters.getKeyType() == KeyType.RSA) {
            result = JWEAlgorithm.RSA_OAEP_256;  // Only supported one, no configuration required
        }
        if (parameters.getKeyType() == KeyType.EC) {
            result = jwtSupportConfiguration.getDefaultJWEAlgorithmEC();
        }
        if (parameters.getKeyType() == KeyType.OCT) {

            result = jwtSupportConfiguration.getDefaultJWEAlgorithmOCT();
        }
        return result;
    }

    private String createSignedJWT(Object data, JWTParametersSigning parameters) {
        JWSObject jwsObject = createJWTObject(data, parameters);
        return jwsObject.serialize();
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
