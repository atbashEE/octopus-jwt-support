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
package be.atbash.ee.security.octopus.nimbus.jwt.proc;


import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.factories.DefaultJWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.BadJOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWEDecrypterFactory;
import be.atbash.ee.security.octopus.nimbus.jose.proc.JWSVerifierFactory;
import be.atbash.ee.security.octopus.nimbus.jwt.*;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEDecrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.Key;
import java.text.ParseException;


/**
 * Default processor of {@link PlainJWT unsecured} (plain),
 * {@link SignedJWT signed} and
 * {@link EncryptedJWT encrypted} JSON Web Tokens (JWTs).
 *
 * <p>Must be configured with the following:
 *
 * <ul>
 *     <li>To process signed JWTs: A {@link #setJWSKeySelector JWS key
 *     selector} using the header  to suggest key candidate(s) for the signature
 *     verification. The key selection procedure is application-specific and
 *     may involve key ID lookup, a certificate check.</li>
 *
 *     <li>To process encrypted JWTs: A {@link #setJWEKeySelector JWE key
 *     selector} using the header to suggest key candidate(s) for decryption.
 *     The key selection procedure is application-specific.</li>
 * </ul>
 *
 *
 * <p>See sections 6 of RFC 7515 (JWS) and RFC 7516 (JWE) for guidelines on key
 * selection.
 *
 * <p>This processor comes with the default {@link DefaultJWSVerifierFactory
 * JWS verifier factory} and the default {@link DefaultJWEDecrypterFactory
 * JWE decrypter factory}; they can construct verifiers / decrypters for all
 * standard JOSE algorithms implemented by the library.
 *
 * <p>Note that for security reasons this processor is hardwired to reject
 * unsecured (plain) JWTs. Override the {@link #process(PlainJWT)}
 * if you need to handle plain JWTs.
 *
 * <p>A {@link DefaultJWTClaimsVerifier default JWT claims verifier} is
 * provided, to perform a minimal check of the claims after a successful JWS
 * verification / JWE decryption. It checks the token expiration (exp) and
 * not-before (nbf) timestamps if these are present. The default JWT claims
 * verifier may be extended to perform additional checks, such as issuer and
 * subject acceptance.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-15
 */
public class DefaultJWTProcessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeySelector.class);

    /**
     * The JWS key selector.
     */
    private KeySelector jwsKeySelector;


    /**
     * The JWE key selector.
     */
    private KeySelector jweKeySelector;


    /**
     * The JWS verifier factory.
     */
    private JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();
    // FIXME This is now not configurable


    /**
     * The JWE decrypter factory.
     */
    private JWEDecrypterFactory jweDecrypterFactory = new DefaultJWEDecrypterFactory();
    // FIXME This is now not configurable


    /**
     * The claims verifier.
     */
    private JWTVerifier claimsVerifier = new DefaultJWTClaimsVerifier();


    public void setJWSKeySelector(KeySelector jwsKeySelector) {

        this.jwsKeySelector = jwsKeySelector;
    }

    public void setJWEKeySelector(KeySelector jweKeySelector) {

        this.jweKeySelector = jweKeySelector;
    }

    public void setJWSVerifierFactory(JWSVerifierFactory factory) {

        jwsVerifierFactory = factory;
    }

    public void setJweDecrypterFactory(JWEDecrypterFactory jweDecrypterFactory) {
        this.jweDecrypterFactory = jweDecrypterFactory;
    }

    public void setJWTClaimsSetVerifier(JWTVerifier claimsVerifier) {

        this.claimsVerifier = claimsVerifier;
    }

    private JWTClaimsSet extractJWTClaimsSet(JWT jwt)
            throws BadJWTException {

        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            // Payload not a JSON object
            throw new BadJWTException(e.getMessage(), e);
        }
    }

    private JWTClaimsSet verifyClaims(JWSHeader header, JWTClaimsSet claimsSet)
            throws BadJWTException {

        if (claimsVerifier != null) {
            if (!claimsVerifier.verify(header, claimsSet)) {
                throw new BadJWTException("JWT Claims validation failed");
            }
        }
        return claimsSet;
    }

    private Key selectKeys(KeySelector keySelector, CommonJWTHeader header, AsymmetricPart asymmetricPart) {

        SelectorCriteria criteria = defineKeyCriteria(header, asymmetricPart);
        return keySelector.selectSecretKey(criteria);

    }

    private SelectorCriteria defineKeyCriteria(CommonJWTHeader header, AsymmetricPart asymmetricPart) {

        String keyID = header.getKeyID();
        URI jwkURI = header.getJWKURL();

        return SelectorCriteria.newBuilder()
                .withId(keyID)
                .withJKU(jwkURI)
                .withAsymmetricPart(asymmetricPart)
                .build();
    }


    public JWTClaimsSet process(String jwtString)
            throws ParseException, JOSEException {

        return process(JWTParser.parse(jwtString));
    }


    public JWTClaimsSet process(JWT jwt) throws JOSEException {

        if (jwt instanceof SignedJWT) {
            return process((SignedJWT) jwt);
        }

        if (jwt instanceof EncryptedJWT) {
            return process((EncryptedJWT) jwt);
        }

        if (jwt instanceof PlainJWT) {
            return process((PlainJWT) jwt);
        }

        // Should never happen
        throw new JOSEException("Unexpected JWT object type: " + jwt.getClass());
    }


    public JWTClaimsSet process(PlainJWT plainJWT) throws JOSEException {

        throw new BadJOSEException("Unsecured (plain) JWTs are rejected, TODO Implementation needs to be done!!");
    }


    public JWTClaimsSet process(SignedJWT signedJWT) throws JOSEException {

        JOSEObjectType objectType = signedJWT.getHeader().getType();
        if (objectType != null && !objectType.equals(JOSEObjectType.JWT)) {
            throw new BadJOSEException("JOSE header \"typ\" (type) \"" + objectType.getType() + "\" not allowed");
        }

        if (jwsKeySelector == null) {
            // JWS key selector may have been deliberately omitted
            throw new BadJOSEException("Signed JWT rejected: No JWS key selector is configured");
        }

        if (jwsVerifierFactory == null) {
            throw new JOSEException("No JWS verifier is configured");
        }

        Key secretKey = selectKeys(jwsKeySelector, signedJWT.getHeader(), AsymmetricPart.PUBLIC);
        if (secretKey == null) {
            secretKey = selectKeys(jwsKeySelector, signedJWT.getHeader(), AsymmetricPart.SYMMETRIC);
        }

        if (secretKey == null) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("(OCT-KEY-010) No or multiple keys found for criteria :%n %s", defineKeyCriteria(signedJWT.getHeader(), AsymmetricPart.PUBLIC)));

            }
            throw new InvalidJWTException(String.format("No key found for keyId '%s'", signedJWT.getHeader().getKeyID()));
        }

        JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), secretKey);

        if (verifier == null) {
            throw new InvalidJWTException("Signed JWT rejected: Another algorithm expected, or no matching key(s) found");
        }

        boolean validSignature = signedJWT.verify(verifier);

        if (validSignature) {
            JWTClaimsSet claimsSet = extractJWTClaimsSet(signedJWT);
            return verifyClaims(signedJWT.getHeader(), claimsSet);
        }

        throw new InvalidJWTException("Signed JWT rejected: Invalid signature");

    }

    public JWTClaimsSet process(EncryptedJWT encryptedJWT) throws JOSEException {

        if (jweKeySelector == null) {
            // JWE key selector may have been deliberately omitted
            throw new BadJOSEException("Encrypted JWT rejected: No JWE key selector is configured");
        }

        if (jweDecrypterFactory == null) {
            throw new JOSEException("No JWE decrypter is configured");
        }

        Key secretKey = selectKeys(jweKeySelector, encryptedJWT.getHeader(), AsymmetricPart.PRIVATE);

        if (secretKey == null) {
            secretKey = selectKeys(jweKeySelector, encryptedJWT.getHeader(), AsymmetricPart.SYMMETRIC);
        }

        if (secretKey == null) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error(String.format("(OCT-KEY-010) No or multiple keys found for criteria :%n %s", defineKeyCriteria(encryptedJWT.getHeader(), AsymmetricPart.PRIVATE)));

            }
            throw new InvalidJWTException(String.format("No key found for keyId '%s'", encryptedJWT.getHeader().getKeyID()));
        }

        JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(encryptedJWT.getHeader(), secretKey);

        if (decrypter == null) {
            throw new BadJOSEException("Encrypted JWT rejected: No matching decrypter(s) found");
        }

        try {
            encryptedJWT.decrypt(decrypter);

        } catch (JOSEException e) {

            throw new BadJWEException("Encrypted JWT rejected: " + e.getMessage(), e);
        }

        if ("JWT".equalsIgnoreCase(encryptedJWT.getHeader().getContentType())) {

            // Handle nested signed JWT, see http://tools.ietf.org/html/rfc7519#section-5.2
            SignedJWT signedJWTPayload = encryptedJWT.getPayload().toSignedJWT();

            if (signedJWTPayload == null) {
                // Cannot parse payload to signed JWT
                throw new BadJWTException("The payload is not a nested signed JWT");
            }

            return process(signedJWTPayload);
        }

        JWTClaimsSet claimsSet = extractJWTClaimsSet(encryptedJWT);
        return verifyClaims(null, claimsSet);  // FIXME Review

    }
}
