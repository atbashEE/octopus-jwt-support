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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.config.JCASupportConfiguration;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.PasswordBasedEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.PBKDF;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.PRFParams;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.PublicAPI;
import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Reviewed
@PublicAPI
public final class JWTParametersBuilder {

    private final Logger logger = LoggerFactory.getLogger(JWTParametersBuilder.class);

    private final JWTEncoding encoding;

    private final Map<String, Object> headerValues;
    private AtbashKey secretKeySigning;

    private AtbashKey secretKeyEncryption;
    private JWTParametersSigning parametersSigning;

    private JWEAlgorithm jweAlgorithm;

    // For the PBE2 keys
    private String kid;
    private char[] password;
    private int iterationCount;

    private JWTParametersBuilder(JWTEncoding encoding) {
        this.encoding = encoding;
        headerValues = new HashMap<>();
    }

    public JWTParametersBuilder withHeader(String key, String value) {
        if (encoding == JWTEncoding.NONE) {
            logger.warn("Header values are not supported with JWTEncoding.NONE");
        }
        headerValues.put(key, value);
        return this;
    }

    // Convenient way for withHeader("jku",url);
    public JWTParametersBuilder withJSONKeyURL(String url) {
        return withHeader("jku", url);
    }

    public JWTParametersBuilder withSecretKeyForSigning(AtbashKey key) {
        if (encoding == JWTEncoding.NONE) {
            logger.warn("SecretKey value is not supported with JWTEncoding.NONE");
        }
        secretKeySigning = key;
        return this;
    }

    public JWTParametersBuilder withSecretKeyForEncryption(AtbashKey key) {
        if (encoding != JWTEncoding.JWE) {
            logger.warn("SecretKey value for encryption only needed for JWTEncoding.JWE");
        }
        secretKeyEncryption = key;
        return this;
    }

    public JWTParametersBuilder withSecretKeyForEncryption(String kid, char[] password) {
        return this.withSecretKeyForEncryption(kid, password, PasswordBasedEncrypter.MIN_RECOMMENDED_ITERATION_COUNT);
    }

    public JWTParametersBuilder withSecretKeyForEncryption(String kid, char[] password, int iterationCount) {
        if (encoding != JWTEncoding.JWE) {
            logger.warn("SecretKey value for encryption only needed for JWTEncoding.JWE");
        }
        jweAlgorithm = JWEAlgorithm.PBES2_HS512_A256KW;
        this.password = password;
        this.iterationCount = iterationCount;
        this.kid = kid;
        return this;
    }

    public JWTParametersBuilder withSigningParameters(JWTParametersSigning parametersSigning) {

        this.parametersSigning = parametersSigning;
        return this;
    }

    public JWTParametersBuilder withJWEAlgorithm(JWEAlgorithm jweAlgorithm) {
        this.jweAlgorithm = jweAlgorithm;
        return this;
    }

    public JWTParameters build() {
        JWTParameters result;

        if (encoding == JWTEncoding.JWE) {
            if (password != null) {
                    defineKeyBasedOnPassword();
            }
        }
        validateParameters();

        switch (encoding) {

            case NONE:
                result = new JWTParametersNone();
                break;
            case JWS:
                result = new JWTParametersSigning(headerValues, secretKeySigning);
                break;
            case JWE:
                if (parametersSigning == null) {
                    parametersSigning = new JWTParametersSigning(headerValues, secretKeySigning);
                }
                result = new JWTParametersEncryption(parametersSigning, headerValues, secretKeyEncryption, jweAlgorithm);
                break;
            default:
                throw new IllegalArgumentException(String.format("Unsupported value for JWTEncoding : %s", encoding));
        }
        return result;
    }

    private void defineKeyBasedOnPassword() {
        byte[] salt = new byte[JwtSupportConfiguration.getInstance().getSaltLengthPasswordBasedEJWEEncryption()];
        JCASupportConfiguration.getInstance().getSecureRandom().nextBytes(salt);

        PRFParams prfParams = PRFParams.resolve(jweAlgorithm);
        secretKeyEncryption = new AtbashKey(kid, PBKDF.deriveKey(password, salt, iterationCount, prfParams));

        headerValues.put("p2s", Base64URLValue.encode(salt));
        headerValues.put("p2c", iterationCount);
    }

    private void validateParameters() {
        switch (encoding) {

            case NONE:
                break;
            case JWS:
                validateJWSParameters();
                break;
            case JWE:
                validateJWEParameters();
                break;
            default:
                throw new IllegalArgumentException(String.format("Unsupported value for JWTEncoding : %s", encoding));
        }

    }

    private void validateJWEParameters() {
        if (secretKeyEncryption == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-106) JWE encoding requires a JWK secret for the encryption");
        }
        if (secretKeySigning == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-112) JWE encoding requires a JWK secret for the signing");
        }

        if (jweAlgorithm == null) {
            return;
            // Default is defined later on.
        }
        KeyType keyType = secretKeyEncryption.getSecretKeyType().getKeyType();
        boolean validJWEAlgorithm = true;
        if (keyType == KeyType.RSA) {
            validJWEAlgorithm = JWEAlgorithm.Family.RSA.contains(jweAlgorithm);
        }
        if (keyType == KeyType.EC) {
            validJWEAlgorithm = JWEAlgorithm.Family.ECDH_ES.contains(jweAlgorithm);

        }
        if (keyType == KeyType.OCT) {
            if (password == null) {
                validJWEAlgorithm = JWEAlgorithm.Family.AES_KW.contains(jweAlgorithm);
            } else {
                validJWEAlgorithm = JWEAlgorithm.Family.PBES2.contains(jweAlgorithm);
            }
        }

        if (!validJWEAlgorithm) {
            throw new AtbashIllegalActionException("(OCT-DEV-111) JWE Algorithm not valid for key type.");
        }

    }

    private void validateJWSParameters() {

        if (secretKeySigning == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-105) JWS encoding requires a JWK secret for the signing");
        }

    }

    public static JWTParametersBuilder newBuilderFor(JWTEncoding encoding) {
        return new JWTParametersBuilder(encoding);
    }
}
