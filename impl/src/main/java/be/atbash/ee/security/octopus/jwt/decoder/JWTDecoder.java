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
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.EncryptedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.DefaultJWTProcessor;
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
import java.text.ParseException;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class JWTDecoder {

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


        EncryptedJWT encryptedJWT = EncryptedJWT.parse(data);

        String keyID = encryptedJWT.getHeader().getKeyID();

        DefaultJWTProcessor processor = new DefaultJWTProcessor();
        processor.setJWSKeySelector(keySelector);
        processor.setJWEKeySelector(keySelector);
        JWTClaimsSet jwtClaimsSet = processor.process(encryptedJWT);

        MetaJWTData metaJWTData = new MetaJWTData(keyID, encryptedJWT.getHeader().getCustomParams());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<T>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(jwtClaimsSet.toJSONObject().toString(), classType, metaJWTData);

    }

    private <T> JWTData<T> readSignedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        DefaultJWTProcessor processor = new DefaultJWTProcessor();
        processor.setJWSKeySelector(keySelector);
        JWTClaimsSet jwtClaimsSet = processor.process(signedJWT);

        if (verifier != null) {
            if (!verifier.verify(signedJWT.getHeader(), signedJWT.getJWTClaimsSet())) {
                throw new InvalidJWTException("JWT verification failed");
            }
        }

        String keyID = signedJWT.getHeader().getKeyID();
        MetaJWTData metaJWTData = new MetaJWTData(keyID, signedJWT.getHeader().getCustomParams());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<T>((T) jwtClaimsSet, metaJWTData);
        }
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
            // FIXME occurences = 1 -> PlainJWT, Add new JWTEncoding
        }
        return result;
    }
}
