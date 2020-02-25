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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.nimbus.jwt.EncryptedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.DefaultJWTProcessor;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.JWTProcessor;
import be.atbash.ee.security.octopus.util.JsonbUtil;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.context.ApplicationScoped;
import javax.json.bind.Jsonb;
import java.text.ParseException;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class JWTDecoder {

    private JWTProcessor jwtProcessor;

    public <T> JWTData<T> decode(String data, Class<T> classType) {
        return decode(data, classType, null, null);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector) {
        return decode(data, classType, keySelector, null);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, JWTVerifier verifier) {
        return decode(data, classType, null, verifier);
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
                case PLAIN:
                    result = readPlainJWT(data, classType);
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
        }
        return result;
    }

    private <T> JWTData<T> readPlainJWT(String data, Class<T> classType) throws ParseException {
        PlainJWT plainJWT = PlainJWT.parse(data);

        MetaJWTData metaJWTData = new MetaJWTData(null, plainJWT.getHeader().getCustomParameters());


        JWTClaimsSet jwtClaimsSet = plainJWT.getJWTClaimsSet();
        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(jwtClaimsSet.toJSONObject().toString(), classType, metaJWTData);
    }

    private <T> JWTData<T> readEncryptedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException {

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(data);

        String keyID = encryptedJWT.getHeader().getKeyID();

        JWTProcessor processor = getJwtProcessor();
        processor.setJWSKeySelector(keySelector);
        processor.setJWEKeySelector(keySelector);
        JWTClaimsSet jwtClaimsSet = processor.process(encryptedJWT);

        if (verifier != null) {
            if (!verifier.verify(encryptedJWT.getHeader(), jwtClaimsSet)) {
                throw new InvalidJWTException("JWT verification failed");
            }
        }

        MetaJWTData metaJWTData = new MetaJWTData(keyID, encryptedJWT.getHeader().getCustomParameters());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(jwtClaimsSet.toJSONObject().toString(), classType, metaJWTData);

    }

    private <T> JWTData<T> readSignedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        JWTProcessor processor = getJwtProcessor();
        processor.setJWSKeySelector(keySelector);
        JWTClaimsSet jwtClaimsSet = processor.process(signedJWT);

        if (verifier != null) {
            if (!verifier.verify(signedJWT.getHeader(), signedJWT.getJWTClaimsSet())) {
                throw new InvalidJWTException("JWT verification failed");
            }
        }

        String keyID = signedJWT.getHeader().getKeyID();
        MetaJWTData metaJWTData = new MetaJWTData(keyID, signedJWT.getHeader().getCustomParameters());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(signedJWT.getPayload().toString(), classType, metaJWTData);
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType) {
        return readJSONString(data, classType, new MetaJWTData());
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType, MetaJWTData metaJWTData) {
        Jsonb jsonb = JsonbUtil.getJsonb();

        return new JWTData<>(jsonb.fromJson(data, classType), metaJWTData);

    }

    private JWTEncoding determineEncoding(String data) {
        JWTEncoding result = null;
        if (data.startsWith("{")) {
            result = JWTEncoding.NONE;
        }

        if (data.startsWith("ey")) {
            int occurrences = StringUtils.countOccurrences(data, '.');
            if (occurrences == 1) {
                result = JWTEncoding.PLAIN;
            }
            if (occurrences == 2) {
                int lastDot = data.lastIndexOf('.');
                if (lastDot == data.length() - 1) {
                    result = JWTEncoding.PLAIN;
                } else {
                    result = JWTEncoding.JWS;
                }
            }
            if (occurrences == 4) {
                result = JWTEncoding.JWE;
            }
        }
        return result;
    }

    private synchronized JWTProcessor getJwtProcessor() {
        if (jwtProcessor == null) {
            Iterator<JWTProcessor> iterator = ServiceLoader.load(JWTProcessor.class).iterator();
            if (iterator.hasNext()) {
                jwtProcessor = iterator.next();
            } else {
                jwtProcessor = new DefaultJWTProcessor();
            }

        }
        return jwtProcessor;
    }
}
