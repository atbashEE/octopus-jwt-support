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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.serializer.spi.SerializerProvider;
import be.atbash.ee.security.octopus.keys.json.AtbashKeyReader;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.*;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbConfig;
import java.net.URI;
import java.security.Key;
import java.text.ParseException;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class JWTDecoder {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeySelector.class);

    // TODO Do we ever need some customer factory implementations? Should we made these configurable?
    private JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();

    private JWEDecrypterFactory jweDecrypterFactory = new DefaultJWEDecrypterFactory();

    public <T> T decode(String data, Class<T> classType) {
        return decode(data, classType, null, null).getData();
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector, JWTVerifier verifier) {
        JWTEncoding encoding = determineEncoding(data);
        if (encoding == null) {
            throw new IllegalArgumentException("Unable to determine the encoding of the data");
        }

        JWTData<T> result;
        try {
            switch (encoding) {

                case NONE:
                    result = readJSONString(data, classType);
                    break;
                case JWS:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWT encoded value");
                    }
                    result = readSignedJWT(data, keySelector, classType, verifier);
                    break;
                case JWE:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWE encoded value");
                    }
                    result = readEncryptedJWT(data, keySelector, classType, verifier);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", encoding));
            }
        } catch (ParseException e) {
            throw new InvalidJWTException("Invalid JWT structure");
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    private <T> JWTData<T> readEncryptedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException, JOSEException {

        JWEObject jweObject = JWEObject.parse(data);

        String keyID = jweObject.getHeader().getKeyID();

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withId(keyID).withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        Key key = keySelector.selectSecretKey(criteria);

        if (key == null) {
            JWEAlgorithm algorithm = jweObject.getHeader().getAlgorithm();
            if (algorithm.equals(JWEAlgorithm.A256KW)) {  // TODO Test also for other algorithms
                // We are using a symmetric algo
                criteria = SelectorCriteria.newBuilder().withId(keyID).build();
                key = keySelector.selectSecretKey(criteria);
            }
        }

        if (key == null) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("(OCT-KEY-010) No or multiple keys found for criteria :%n %s", criteria.toString()));
            }
            throw new InvalidJWTException(String.format("No key found for %s", keyID));
        }

        // Decrypt with private key
        JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(jweObject.getHeader(), key);
        jweObject.decrypt(decrypter);

        // Now we have a signedJWT
        return readSignedJWT(jweObject.getPayload().toString(), keySelector, classType, verifier);

    }

    private <T> JWTData<T> readSignedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        String keyID = signedJWT.getHeader().getKeyID();
        URI jwkURI = signedJWT.getHeader().getJWKURL();

        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withId(keyID)
                .withJKU(jwkURI)
                .withAsymmetricPart(AsymmetricPart.PUBLIC)
                .build();
        Key key = keySelector.selectSecretKey(criteria);

        if (key == null) {
            if (signedJWT.getHeader().getAlgorithm() == JWSAlgorithm.HS256) { // FIXME Other algorithms
                criteria = SelectorCriteria.newBuilder()
                        .withId(keyID)
                        .withJKU(jwkURI)
                        .build();
                key = keySelector.selectSecretKey(criteria);
            }
        }
        if (key == null) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("(OCT-KEY-010) No or multiple keys found for criteria :%n %s", criteria.toString()));
            }
            throw new InvalidJWTException(String.format("No key found for keyId '%s'", keyID));
        }

        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key);

        if (!signedJWT.verify(jwsVerifier)) {
            throw new InvalidJWTException("JWT Signature verification failed");
        }

        if (verifier != null) {
            if (!verifier.verify(signedJWT.getHeader(), signedJWT.getJWTClaimsSet())) {
                throw new InvalidJWTException("JWT verification failed");
            }
        }
        MetaJWTData metaJWTData = new MetaJWTData(keyID, signedJWT.getHeader().getCustomParams());

        return readJSONString(signedJWT.getPayload().toString(), classType, metaJWTData);
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType) {
        return readJSONString(data, classType, new MetaJWTData());
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType, MetaJWTData metaJWTData) {
        JsonbConfig config = new JsonbConfig();

        config.withDeserializers(SerializerProvider.getInstance().getDeserializers());

        Jsonb jsonb = JsonbBuilder.create(config);

        return new JWTData<>(jsonb.fromJson(data, classType), metaJWTData);

    }

    private JWTEncoding determineEncoding(String data) {
        JWTEncoding result = null;
        if (data.startsWith("{")) {
            result = JWTEncoding.NONE;
        }

        if (data.startsWith("ey")) {
            int occurrences = StringUtils.countOccurrences(data, '.');
            if (occurrences == 2) {
                result = JWTEncoding.JWS;
            }
            if (occurrences == 4) {
                result = JWTEncoding.JWE;
            }
        }
        return result;
    }
}
