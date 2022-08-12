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
package be.atbash.ee.security.octopus.nimbus.jwk;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.util.*;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.Serializable;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;


/**
 * The base abstract class for JSON Web Keys (JWKs). It serialises to a JSON
 * object.
 *
 * <p>The following JSON object members are common to all JWK types:
 *
 * <ul>
 *     <li>{@link #getKeyType kty} (required)
 *     <li>{@link #getKeyUse use} (optional)
 *     <li>{@link #getKeyOperations key_ops} (optional)
 *     <li>{@link #getKeyID kid} (optional)
 *     <li>{@link #getX509CertURL()  x5u} (optional)
 *     <li>{@link #getX509CertSHA256Thumbprint()  x5t#S256} (optional)
 *     <li>{@link #getX509CertChain() x5c} (optional)
 *     <li>{@link #getKeyStore()}
 * </ul>
 *
 * <p>Example JWK (of the Elliptic Curve type):
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov, Justin Richer and Stefan Larsson
 */
public abstract class JWK implements Serializable {


    private static final long serialVersionUID = 1L;


    /**
     * The MIME type of JWK objects:
     * {@code application/jwk+json; charset=UTF-8}
     */
    public static final String MIME_TYPE = "application/jwk+json; charset=UTF-8";


    /**
     * The key type, required.
     */
    private final KeyType kty;


    /**
     * The key use, optional.
     */
    private final KeyUse use;


    /**
     * The key operations, optional.
     */
    private final Set<KeyOperation> ops;


    /**
     * The intended JOSE algorithm for the key, optional.
     */
    private final Algorithm alg;


    /**
     * The key ID, optional.
     */
    private final String kid;


    /**
     * X.509 certificate URL, optional.
     */
    private final URI x5u;

    /**
     * X.509 certificate SHA-256 thumbprint, optional.
     */
    private final Base64URLValue x5t256;


    /**
     * The X.509 certificate chain, optional.
     */
    private final List<Base64Value> x5c;


    /**
     * The parsed X.509 certificate chain, optional.
     */
    private final List<X509Certificate> parsedX5c;


    /**
     * Reference to the underlying key store, {@code null} if none.
     */
    private final KeyStore keyStore;


    /**
     * Creates a new JSON Web Key (JWK).
     *
     * @param kty    The key type. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param alg    The intended JOSE algorithm for the key, {@code null}
     *               if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param keyStore     Reference to the underlying key store, {@code null} if
     *               none.
     */
    protected JWK(KeyType kty,
                  KeyUse use,
                  Set<KeyOperation> ops,
                  Algorithm alg,
                  String kid,
                  URI x5u,
                  Base64URLValue x5t256,
                  List<Base64Value> x5c,
                  KeyStore keyStore) {

        if (kty == null) {
            throw new IllegalArgumentException("The key type \"kty\" parameter must not be null");
        }

        this.kty = kty;

        if (!KeyUseAndOpsConsistency.areConsistent(use, ops)) {
            throw new IllegalArgumentException("The key use \"use\" and key options \"key_opts\" parameters are not consistent, " +
                    "see RFC 7517, section 4.3");
        }

        this.use = use;
        this.ops = ops;

        this.alg = alg;
        this.kid = kid;

        this.x5u = x5u;
        this.x5t256 = x5t256;

        if (x5c != null && x5c.isEmpty()) {
            throw new IllegalArgumentException("The X.509 certificate chain \"x5c\" must not be empty");
        }
        this.x5c = x5c;

        try {
            parsedX5c = X509CertChainUtils.parse(x5c);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid X.509 certificate chain \"x5c\": " + e.getMessage(), e);
        }

        this.keyStore = keyStore;
    }


    /**
     * Gets the type ({@code kty}) of this JWK.
     *
     * @return The key type.
     */
    public KeyType getKeyType() {

        return kty;
    }


    /**
     * Gets the use ({@code use}) of this JWK.
     *
     * @return The key use, {@code null} if not specified or if the key is
     * intended for signing as well as encryption.
     */
    public KeyUse getKeyUse() {

        return use;
    }


    /**
     * Gets the operations ({@code key_ops}) for this JWK.
     *
     * @return The key operations, {@code null} if not specified.
     */
    public Set<KeyOperation> getKeyOperations() {

        return ops;
    }


    /**
     * Gets the intended JOSE algorithm ({@code alg}) for this JWK.
     *
     * @return The intended JOSE algorithm, {@code null} if not specified.
     */
    public Algorithm getAlgorithm() {

        return alg;
    }


    /**
     * Gets the ID ({@code kid}) of this JWK. The key ID can be used to
     * match a specific key. This can be used, for instance, to choose a
     * key within a {@link JWKSet} during key rollover. The key ID may also
     * correspond to a JWS/JWE {@code kid} header parameter value.
     *
     * @return The key ID, {@code null} if not specified.
     */
    public String getKeyID() {

        return kid;
    }


    /**
     * Gets the X.509 certificate URL ({@code x5u}) of this JWK.
     *
     * @return The X.509 certificate URL, {@code null} if not specified.
     */
    public URI getX509CertURL() {

        return x5u;
    }

    /**
     * Gets the X.509 certificate SHA-256 thumbprint ({@code x5t#S256}) of
     * this JWK.
     *
     * @return The X.509 certificate SHA-256 thumbprint, {@code null} if
     * not specified.
     */
    public Base64URLValue getX509CertSHA256Thumbprint() {

        return x5t256;
    }


    /**
     * Gets the X.509 certificate chain ({@code x5c}) of this JWK.
     *
     * @return The X.509 certificate chain as a unmodifiable list,
     * {@code null} if not specified.
     */
    public List<Base64Value> getX509CertChain() {

        if (x5c == null) {
            return null;
        }

        return Collections.unmodifiableList(x5c);
    }


    /**
     * Gets the parsed X.509 certificate chain ({@code x5c}) of this JWK.
     *
     * @return The X.509 certificate chain as a unmodifiable list,
     * {@code null} if not specified.
     */
    public List<X509Certificate> getParsedX509CertChain() {

        if (parsedX5c == null) {
            return null;
        }

        return Collections.unmodifiableList(parsedX5c);
    }


    /**
     * Returns a reference to the underlying key store.
     *
     * @return The underlying key store, {@code null} if none.
     */
    public KeyStore getKeyStore() {

        return keyStore;
    }


    /**
     * Returns the required JWK parameters. Intended as input for JWK
     * thumbprint computation. See RFC 7638 for more information.
     *
     * @return The required JWK parameters, sorted alphanumerically by key
     * name and ready for JSON serialisation.
     */
    public abstract LinkedHashMap<String, String> getRequiredParams();


    /**
     * Computes the SHA-256 thumbprint of this JWK. See RFC 7638 for more
     * information.
     *
     * @return The SHA-256 thumbprint.
     */
    public Base64URLValue computeThumbprint() {

        return computeThumbprint("SHA-256");
    }


    /**
     * Computes the thumbprint of this JWK using the specified hash
     * algorithm. See RFC 7638 for more information.
     *
     * @param hashAlg The hash algorithm. Must not be {@code null}.
     * @return The SHA-256 thumbprint.
     */
    public Base64URLValue computeThumbprint(String hashAlg) {

        return ThumbprintUtils.compute(hashAlg, this);
    }


    /**
     * Returns {@code true} if this JWK contains private or sensitive
     * (non-public) parameters.
     *
     * @return {@code true} if this JWK contains private parameters, else
     * {@code false}.
     */
    public abstract boolean isPrivate();


    /**
     * Creates a copy of this JWK with all private or sensitive parameters
     * removed.
     *
     * @return The newly created public JWK, or {@code null} if none can be
     * created.
     */
    public abstract JWK toPublicJWK();


    /**
     * Returns the size of this JWK.
     *
     * @return The JWK size, in bits.
     */
    public abstract int size();


    /**
     * Returns a JSON object representation of this JWK. This method is
     * intended to be called from extending classes.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "kty" : "RSA",
     *   "use" : "sig",
     *   "kid" : "fd28e025-8d24-48bc-a51a-e2ffc8bc274b"
     * }
     * </pre>
     *
     * @return The JSON object representation.
     */
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();

        result.add(JWKIdentifiers.KEY_TYPE, kty.getValue());

        if (use != null) {
            result.add(JWKIdentifiers.PUBLIC_KEY_USE, use.identifier());
        }

        if (ops != null) {

            JsonArrayBuilder opsValues = Json.createArrayBuilder();

            for (KeyOperation op : ops) {
                opsValues.add(op.identifier());
            }

            result.add(JWKIdentifiers.KEY_OPS, opsValues);
        }

        if (alg != null) {
            result.add(JWKIdentifiers.ALGORITHM, alg.getName());
        }

        if (kid != null) {
            result.add(JWKIdentifiers.KEY_ID, kid);
        }

        if (x5u != null) {
            result.add(JWKIdentifiers.X_509_URL, x5u.toString());
        }

        if (x5t256 != null) {
            result.add(JWKIdentifiers.X_509_CERT_SHA_256_THUMBPRINT, x5t256.toString());
        }

        if (x5c != null) {
            JsonArrayBuilder stringValues = Json.createArrayBuilder();

            for (Base64Value base64 : x5c) {
                stringValues.add(base64.toString());
            }
            result.add(JWKIdentifiers.X_509_CERT_CHAIN, stringValues);
        }

        return result;
    }


    /**
     * Returns the JSON object string representation of this JWK.
     *
     * @return The JSON object string representation.
     */
    public String toJSONString() {
        return toJSONObject().build().toString();
    }


    /**
     * @see #toJSONString
     */
    @Override
    public String toString() {

        return toJSONObject().build().toString();
    }


    /**
     * Parses a JWK from the specified JSON object string representation.
     * The JWK must be an {@link ECKey}, an {@link RSAKey}, or a
     * {@link OctetSequenceKey}.
     *
     * @param value The JSON object string to parse. Must not be {@code null}.
     * @return The JWK.
     * @throws ParseException If the string couldn't be parsed to a
     *                        supported JWK.
     */
    public static JWK parse(String value)
            throws ParseException {

        return parse(JSONObjectUtils.parse(value));
    }


    /**
     * Parses a JWK from the specified JSON object representation. The JWK
     * must be an {@link ECKey}, an {@link RSAKey}, or a
     * {@link OctetSequenceKey}.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The JWK.
     * @throws ParseException If the JSON object couldn't be parsed to a
     *                        supported JWK.
     */
    public static JWK parse(JsonObject jsonObject)
            throws ParseException {

        if (!jsonObject.containsKey(JWKIdentifiers.KEY_TYPE)) {
            throw new ParseException("Missing key type '" + JWKIdentifiers.KEY_TYPE + "' parameter", 0);
        }
        KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, JWKIdentifiers.KEY_TYPE));

        if (kty == KeyType.EC) {

            return ECKey.parse(jsonObject);

        } else if (kty == KeyType.RSA) {

            return RSAKey.parse(jsonObject);

        } else if (kty == KeyType.OCT) {

            return OctetSequenceKey.parse(jsonObject);

        } else if (kty == KeyType.OKP) {

            return OctetKeyPair.parse(jsonObject);

        } else {
            // Ignore unknown key type
            // https://tools.ietf.org/html/rfc7517#section-5

            return null;
        }
    }


    /**
     * Parses a public {@link RSAKey RSA} or {@link ECKey EC JWK} from the
     * specified X.509 certificate. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * <p>Sets the following JWK parameters:
     *
     * <ul>
     *     <li>For an EC key the curve is obtained from the subject public
     *         key info algorithm parameters.
     *     <li>The JWK use inferred by {@link KeyUse#from}.
     *     <li>The JWK ID from the X.509 serial number (in base 10).
     *     <li>The JWK X.509 certificate chain (this certificate only).
     *     <li>The JWK X.509 certificate SHA-256 thumbprint.
     * </ul>
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return The public RSA or EC JWK.
     */
    public static JWK parse(X509Certificate cert) {

        if (cert.getPublicKey() instanceof RSAPublicKey) {
            return RSAKey.parse(cert);
        } else if (cert.getPublicKey() instanceof ECPublicKey) {
            return ECKey.parse(cert);
        } else {
            throw new JOSEException("Unsupported public key algorithm: " + cert.getPublicKey().getAlgorithm());
        }
    }


    /**
     * Parses a public {@link RSAKey RSA} or {@link ECKey EC JWK} from the
     * specified PEM-encoded X.509 certificate. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * <p>Sets the following JWK parameters:
     *
     * <ul>
     *     <li>For an EC key the curve is obtained from the subject public
     *         key info algorithm parameters.
     *     <li>The JWK use inferred by {@link KeyUse#from}.
     *     <li>The JWK ID from the X.509 serial number (in base 10).
     *     <li>The JWK X.509 certificate chain (this certificate only).
     *     <li>The JWK X.509 certificate SHA-256 thumbprint.
     * </ul>
     *
     * @param pemEncodedCert The PEM-encoded X.509 certificate. Must not be
     *                       {@code null}.
     * @return The public RSA or EC JWK.
     */
    public static JWK parseFromPEMEncodedX509Cert(String pemEncodedCert) {

        X509Certificate cert = X509CertUtils.parse(pemEncodedCert);

        if (cert == null) {
            throw new JOSEException("Couldn't parse PEM-encoded X.509 certificate");
        }

        return parse(cert);
    }


    /**
     * Loads a JWK from the specified JCE key store. The JWK can be a
     * public / private {@link RSAKey RSA key}, a public / private
     * {@link ECKey EC key}, or a {@link OctetSequenceKey secret key}.
     * Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * @param keyStore The key store. Must not be {@code null}.
     * @param alias    The alias. Must not be {@code null}.
     * @param pin      The pin to unlock the private key if any, empty or
     *                 {@code null} if not required.
     * @return The public / private RSA or EC JWK, or secret JWK, or
     * {@code null} if no key with the specified alias was found.
     * @throws KeyStoreException On a key store exception.
     */
    public static JWK load(KeyStore keyStore, String alias, char[] pin)
            throws KeyStoreException {

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);

        if (cert == null) {
            // Try secret key
            return OctetSequenceKey.load(keyStore, alias, pin);
        }

        if (cert.getPublicKey() instanceof RSAPublicKey) {
            return RSAKey.load(keyStore, alias, pin);
        } else if (cert.getPublicKey() instanceof ECPublicKey) {
            return ECKey.load(keyStore, alias, pin);
        } else {
            throw new JOSEException("Unsupported public key algorithm: " + cert.getPublicKey().getAlgorithm());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof JWK)) {
            return false;
        }
        JWK jwk = (JWK) o;
        return Objects.equals(kty, jwk.kty) &&
                Objects.equals(use, jwk.use) &&
                Objects.equals(ops, jwk.ops) &&
                Objects.equals(alg, jwk.alg) &&
                Objects.equals(kid, jwk.kid) &&
                Objects.equals(x5u, jwk.x5u) &&
                Objects.equals(x5t256, jwk.x5t256) &&
                Objects.equals(x5c, jwk.x5c) &&
                Objects.equals(keyStore, jwk.keyStore);
    }


    @Override
    public int hashCode() {
        return Objects.hash(kty, use, ops, alg, kid, x5u, x5t256, x5c, parsedX5c, keyStore);
    }
}
