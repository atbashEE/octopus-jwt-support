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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.jwt.JWTValidationConstant;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObject;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.slf4j.MDC;

import javax.json.Json;
import javax.json.JsonObject;
import java.text.ParseException;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * JSON Web Signature (JWS) secured object. This class is thread-safe.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWSObject extends JOSEObject {


    /**
     * Enumeration of the states of a JSON Web Signature (JWS) object.
     */
    public enum State {


        /**
         * The JWS object is created but not signed yet.
         */
        UNSIGNED,


        /**
         * The JWS object is signed but its signature is not verified.
         */
        SIGNED,


        /**
         * The JWS object is signed and its signature was successfully verified.
         */
        VERIFIED
    }


    /**
     * The header.
     */
    private final JWSHeader header;


    /**
     * The signing input for this JWS object.
     *
     */
    private final String signingInputString;


    /**
     * The signature, {@code null} if not signed.
     */
    private Base64URLValue signature;


    /**
     * The JWS object state.
     */
    private State state;


    /**
     * Creates a new to-be-signed JSON Web Signature (JWS) object with the
     * specified header and payload. The initial state will be
     * {@link State#UNSIGNED unsigned}.
     *
     * @param header  The JWS header. Must not be {@code null}.
     * @param payload The payload. Must not be {@code null}.
     */
    public JWSObject(JWSHeader header, Payload payload) {

        if (header == null) {

            throw new IllegalArgumentException("The JWS header must not be null");
        }

        this.header = header;

        if (payload == null) {

            throw new IllegalArgumentException("The payload must not be null");
        }

        setPayload(payload);

        signingInputString = composeSigningInput();
        signature = null;

        state = State.UNSIGNED;
    }

    /**
     * Creates a new signed JSON Web Signature (JWS) object with the
     * specified serialised parts. The state will be
     * {@link State#SIGNED signed}.
     *
     * @param firstPart  The first part, corresponding to the JWS header.
     *                   Must not be {@code null}.
     * @param secondPart The second part, corresponding to the payload. Must
     *                   not be {@code null}.
     * @param thirdPart  The third part, corresponding to the signature.
     *                   Must not be {@code null}.
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public JWSObject(Base64URLValue firstPart, Base64URLValue secondPart, Base64URLValue thirdPart)
            throws ParseException {
        this(firstPart, new Payload(secondPart), thirdPart);
    }

    /*
     * Creates a new signed JSON Web Signature (JWS) object with the
     * specified serialised parts and payload which can be optionally
     * unencoded (RFC 7797). The state will be {@link State#SIGNED signed}.
     *
     * @param firstPart The first part, corresponding to the JWS header.
     *                  Must not be {@code null}.
     * @param payload   The payload. Must not be {@code null}.
     * @param thirdPart The third part, corresponding to the signature.
     *                  Must not be {@code null}.
     *
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public JWSObject(Base64URLValue firstPart, Payload payload, Base64URLValue thirdPart)
            throws ParseException {

        if (firstPart == null) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The token has no header");
            throw new IllegalArgumentException("The first part must not be null");
        }
        try {
            this.header = JWSHeader.parse(firstPart);
        } catch (ParseException e) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The token has an invalid header");
            throw new ParseException("Invalid JWS header: " + e.getMessage(), 0);
        }

        if (payload == null) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The token has no payload section");
            throw new IllegalArgumentException("The payload (second part) must not be null");
        }
        setPayload(payload);

        signingInputString = composeSigningInput();

        if (thirdPart == null) {
            MDC.put(JWTValidationConstant.JWT_VERIFICATION_FAIL_REASON, "The token has no signature section");
            throw new IllegalArgumentException("The third part must not be null");
        }
        signature = thirdPart;
        state = State.SIGNED; // but signature not verified yet!


        setParsedParts(firstPart, payload.toBase64URL(), thirdPart);

    }


    @Override
    public JWSHeader getHeader() {

        return header;
    }


    /**
     * Composes the signing input string from the header and payload.
     *
     * @return The signing input string.
     */
    private String composeSigningInput() {

        if (header.isBase64URLEncodePayload()) {
            return getHeader().toBase64URL().toString() + '.' + getPayload().toBase64URL().toString();
        } else {
            return getHeader().toBase64URL().toString() + '.' + getPayload().toString();
        }
    }


    /**
     * Returns the signing input for this JWS object.
     *
     * <p>Format:
     *
     * <pre>
     * [header-base64url].[payload-base64url]
     * </pre>
     *
     * @return The signing input, to be passed to a JWS signer or verifier.
     */
    public byte[] getSigningInput() {

        return signingInputString.getBytes(UTF_8);
    }


    /**
     * Returns the signature of this JWS object.
     *
     * @return The signature, {@code null} if the JWS object is not signed
     * yet.
     */
    public Base64URLValue getSignature() {

        return signature;
    }


    /**
     * Returns the state of this JWS object.
     *
     * @return The state.
     */
    public State getState() {

        return state;
    }


    /**
     * Ensures the current state is {@link State#UNSIGNED unsigned}.
     *
     * @throws IllegalStateException If the current state is not unsigned.
     */
    private void ensureUnsignedState() {

        if (state != State.UNSIGNED) {

            throw new IllegalStateException("The JWS object must be in an unsigned state");
        }
    }


    /**
     * Ensures the current state is {@link State#SIGNED signed} or
     * {@link State#VERIFIED verified}.
     *
     * @throws IllegalStateException If the current state is not signed or
     *                               verified.
     */
    private void ensureSignedOrVerifiedState() {

        if (state != State.SIGNED && state != State.VERIFIED) {

            throw new IllegalStateException("The JWS object must be in a signed or verified state");
        }
    }


    /**
     * Ensures the specified JWS signer supports the algorithm of this JWS
     * object.
     */
    private void ensureJWSSignerSupport(JWSSigner signer) {

        if (!signer.supportedJWSAlgorithms().contains(getHeader().getAlgorithm())) {

            throw new JOSEException("The \"" + getHeader().getAlgorithm() +
                    "\" algorithm is not allowed or supported by the JWS signer: Supported algorithms: " + signer.supportedJWSAlgorithms());
        }
    }


    /**
     * Signs this JWS object with the specified signer. The JWS object must
     * be in a {@link State#UNSIGNED unsigned} state.
     *
     * @param signer The JWS signer. Must not be {@code null}.
     * @throws IllegalStateException If the JWS object is not in an
     *                               {@link State#UNSIGNED unsigned state}.
     */
    public synchronized void sign(JWSSigner signer) {

        ensureUnsignedState();

        ensureJWSSignerSupport(signer);

        signature = signer.sign(getHeader(), getSigningInput());


        state = State.SIGNED;
    }


    /**
     * Checks the signature of this JWS object with the specified verifier.
     * The JWS object must be in a {@link State#SIGNED signed} state.
     *
     * @param verifier The JWS verifier. Must not be {@code null}.
     * @return {@code true} if the signature was successfully verified,
     * else {@code false}.
     * @throws IllegalStateException If the JWS object is not in a
     *                               {@link State#SIGNED signed} or
     *                               {@link State#VERIFIED verified state}.
     */
    public synchronized boolean verify(JWSVerifier verifier) {

        ensureSignedOrVerifiedState();

        boolean verified = verifier.verify(getHeader(), getSigningInput(), getSignature());

        if (verified) {

            state = State.VERIFIED;
        }

        return verified;
    }


    /**
     * Serialises this JWS object to its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters. It
     * must be in a {@link State#SIGNED signed} or
     * {@link State#VERIFIED verified} state.
     *
     * <pre>
     * [header-base64url].[payload-base64url].[signature-base64url]
     * </pre>
     *
     * @return The serialised JWS object.
     * @throws IllegalStateException If the JWS object is not in a
     *                               {@link State#SIGNED signed} or
     *                               {@link State#VERIFIED verified} state.
     */
    @Override
    public String serialize() {
        return serialize(false);
    }


    /**
     * Serialises this JWS object to its compact format consisting of
     * Base64URL-encoded parts delimited by period ('.') characters. It
     * must be in a {@link State#SIGNED signed} or
     * {@link State#VERIFIED verified} state.
     *
     * @param detachedPayload {@code true} to return a serialised object
     *                        with a detached payload compliant with RFC
     *                        7797, {@code false} for regular JWS
     *                        serialisation.
     * @return The serialised JOSE object.
     * @throws IllegalStateException If the JOSE object is not in a state
     *                               that permits serialisation.
     */
    public String serialize(boolean detachedPayload) {
        ensureSignedOrVerifiedState();

        if (detachedPayload) {
            return header.toBase64URL().toString() + '.' + '.' + signature.toString();
        }

        return signingInputString + '.' + signature.toString();
    }

    /**
     * Serialize to the Flattened JWS JSON Serialization.
     *
     * @return JsonObject with serialized content of JWS.
     */
    public JsonObject serializeToJson() {
        return Json.createObjectBuilder()
                .add("header", getHeader().toJSONObject().build())
                .add("protected", getHeader().toBase64URL().toString())
                .add("payload", getPayload().toBase64URL().toString())
                .add("signature", getSignature().toString())
                .build();
    }

    /**
     * Parses a JWS object from the specified string in compact format. The
     * parsed JWS object will be given a {@link State#SIGNED} state.
     *
     * @param value The string to parse. Must not be {@code null}.
     * @return The JWS object.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        JWS object.
     */
    public static JWSObject parse(String value)
            throws ParseException {

        Base64URLValue[] parts = JOSEObject.split(value);

        if (parts.length != 3) {

            throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
        }

        return new JWSObject(parts[0], parts[1], parts[2]);
    }
}
