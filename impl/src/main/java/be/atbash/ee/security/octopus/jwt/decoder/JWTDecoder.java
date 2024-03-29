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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
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
import org.slf4j.MDC;

import javax.enterprise.context.ApplicationScoped;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import java.text.ParseException;
import java.util.*;

/**
 *
 */
@PublicAPI
@ApplicationScoped
public class JWTDecoder {

    private JWTProcessor jwtProcessor;

    public <T> JWTData<T> decode(String data, Class<T> classType) {
        return decode(data, classType, null, (JWTVerifier) null);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector) {
        return decode(data, classType, keySelector, (JWTVerifier) null);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, JWTVerifier verifier) {
        return decode(data, classType, null, verifier);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector, String... defCritHeaders) {
        return decode(data, classType, keySelector, null, defCritHeaders);
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector, JWTVerifier verifier, String... defCritHeaders) {
        JWTEncoding encoding = determineEncoding(data);
        if (encoding == null) {
            // These messages are in function of JWT validation by Atbash Runtime so have slightly narrow meaning of the provided parameters.
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "Unable to determine the encoding of the provided token");
            throw new IllegalArgumentException("Unable to determine the encoding of the data");
        }
        MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, String.format("The encoding of the provided token : %s", encoding));

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
                    result = readSignedJWT(data, keySelector, classType, verifier, getDefCritHeaders(defCritHeaders));
                    break;
                case JWE:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWE encoded value");
                    }
                    result = readEncryptedJWT(data, keySelector, classType, verifier, getDefCritHeaders(defCritHeaders));
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", encoding));
            }
        } catch (ParseException e) {
            // These messages are in function of JWT validation by Atbash Runtime so have slightly narrow meaning of the provided parameters.
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The structure of the provided token was not valid");
            throw new InvalidJWTException("Invalid JWT structure", e);
        }
        return result;
    }

    private HashSet<String> getDefCritHeaders(String[] defCritHeaders) {
        if (defCritHeaders == null) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(defCritHeaders));
    }

    private <T> JWTData<T> readPlainJWT(String data, Class<T> classType) throws ParseException {
        PlainJWT plainJWT = PlainJWT.parse(data);

        return handlePlainJWT(plainJWT, classType);
    }

    private <T> JWTData<T> readEncryptedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) throws ParseException {

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(data);

        return handleEncryptedJWT(encryptedJWT, keySelector, classType, verifier, defCritHeaders);

    }

    private <T> JWTData<T> readSignedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        return handleSignedJWT(signedJWT, keySelector, classType, verifier, defCritHeaders);
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType) {
        return readJSONString(data, classType, new MetaJWTData());
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType, MetaJWTData metaJWTData) {
        Jsonb jsonb = JsonbUtil.getJsonb();

        return new JWTData<>(jsonb.fromJson(data, classType), metaJWTData);

    }

    /**
     * Determine the encoding of the data. When it starts with { the encoding is none as it is plain
     * JSON. When starting with ey and depending on the number of . found, the encoding is JWT or JWE.
     * Otherwise the encoding is null.
     * Note that the algorithm gives only an indication and that a wrong encoding can be returned (only false negatives)
     * @param data the
     * @return The encoding or null.
     */
    public JWTEncoding determineEncoding(String data) {
        if (data == null) {
            return null;
        }
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

    public <T> JWTData<T> decode(JsonObject data, Class<T> classType) {
        return decode(data, classType, null, (JWTVerifier) null);
    }

    public <T> JWTData<T> decode(JsonObject data, Class<T> classType, KeySelector keySelector) {
        return decode(data, classType, keySelector, (JWTVerifier) null);
    }

    public <T> JWTData<T> decode(JsonObject data, Class<T> classType, JWTVerifier verifier) {
        return decode(data, classType, null, verifier);
    }

    public <T> JWTData<T> decode(JsonObject data, Class<T> classType, KeySelector keySelector, String... defCritHeaders) {
        return decode(data, classType, keySelector, null, defCritHeaders);
    }

    public <T> JWTData<T> decode(JsonObject data, Class<T> classType, KeySelector keySelector, JWTVerifier verifier, String... defCritHeaders) {
        JWTEncoding encoding = determineEncoding(data);
        if (encoding == null) {
            throw new IllegalArgumentException("Unable to determine the encoding of the data");
        }

        JWTData<T> result;
        try {
            switch (encoding) {

                case PLAIN:
                    result = readPlainJWT(data, classType);
                    break;
                case JWS:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWT encoded value");
                    }
                    result = readSignedJWT(data, keySelector, classType, verifier, getDefCritHeaders(defCritHeaders));
                    break;
                case JWE:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWE encoded value");
                    }
                    result = readEncryptedJWT(data, keySelector, classType, verifier, getDefCritHeaders(defCritHeaders));
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", encoding));
            }
        } catch (ParseException e) {
            throw new InvalidJWTException("Invalid JWT structure", e);
        }
        return result;
    }

    private JWTEncoding determineEncoding(JsonObject data) {
        if (data == null) {
            return null;
        }
        if (!(data.containsKey("header") || data.containsKey("protected")) && !data.containsKey("payload")) {
            // payload and (header or protected) is required
            return null;
        }
        JWTEncoding result = JWTEncoding.PLAIN;
        if (data.containsKey("signature")) {
            result = JWTEncoding.JWS;
        }
        if (data.containsKey("encrypted_key") && data.containsKey("iv") && data.containsKey("ciphertext") && data.containsKey("tag")) {
            result = JWTEncoding.JWE;
        }
        return result;
    }

    private <T> JWTData<T> readPlainJWT(JsonObject data, Class<T> classType) throws ParseException {
        PlainJWT plainJWT = PlainJWT.parse(data);

        return handlePlainJWT(plainJWT, classType);
    }

    private <T> JWTData<T> handlePlainJWT(PlainJWT plainJWT, Class<T> classType) throws ParseException {
        MetaJWTData metaJWTData = new MetaJWTData(null, plainJWT.getHeader().getCustomParameters());

        JWTClaimsSet jwtClaimsSet = plainJWT.getJWTClaimsSet();
        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(jwtClaimsSet.toJSONObject().toString(), classType, metaJWTData);
    }

    private <T> JWTData<T> readSignedJWT(JsonObject data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        return handleSignedJWT(signedJWT, keySelector, classType, verifier, defCritHeaders);
    }

    private <T> JWTData<T> handleSignedJWT(SignedJWT signedJWT, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) throws ParseException {
        JWTProcessor processor = getJwtProcessor();
        processor.setJWSKeySelector(keySelector);

        Set<String> allCritHeaders = assembleAllCritHeaders(verifier, defCritHeaders);

        processor.setDeferredCritHeaders(allCritHeaders);
        JWTClaimsSet jwtClaimsSet = processor.process(signedJWT);

        if (verifier != null && !verifier.verify(signedJWT.getHeader(), signedJWT.getJWTClaimsSet())) {
            throw new InvalidJWTException("JWT verification failed");
        }

        String keyID = signedJWT.getHeader().getKeyID();
        MetaJWTData metaJWTData = new MetaJWTData(keyID, signedJWT.getHeader().getCustomParameters());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(signedJWT.getPayload().toString(), classType, metaJWTData);
    }

    private Set<String> assembleAllCritHeaders(JWTVerifier claimsVerifier, Set<String> defCritHeaders) {
        Set<String> result = defCritHeaders;
        if (result == null) {
            result = new HashSet<>();
        }
        if (claimsVerifier != null) {
            result.addAll(claimsVerifier.getSupportedCritHeaderValues());
        }
        return result;
    }

    private <T> JWTData<T> readEncryptedJWT(JsonObject data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) throws ParseException {

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(data);

        return handleEncryptedJWT(encryptedJWT, keySelector, classType, verifier, defCritHeaders);

    }

    private <T> JWTData<T> handleEncryptedJWT(EncryptedJWT encryptedJWT, KeySelector keySelector, Class<T> classType, JWTVerifier verifier, Set<String> defCritHeaders) {
        String keyID = encryptedJWT.getHeader().getKeyID();

        JWTProcessor processor = getJwtProcessor();
        processor.setJWSKeySelector(keySelector);
        processor.setJWEKeySelector(keySelector);
        processor.setDeferredCritHeaders(defCritHeaders);
        JWTClaimsSet jwtClaimsSet = processor.process(encryptedJWT);

        if (verifier != null && !verifier.verify(encryptedJWT.getHeader(), jwtClaimsSet)) {
            throw new InvalidJWTException("JWT verification failed");
        }

        MetaJWTData metaJWTData = new MetaJWTData(keyID, encryptedJWT.getHeader().getCustomParameters());

        if (classType.equals(JWTClaimsSet.class)) {
            return new JWTData<>((T) jwtClaimsSet, metaJWTData);
        }
        return readJSONString(jwtClaimsSet.toJSONObject().toString(), classType, metaJWTData);
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
