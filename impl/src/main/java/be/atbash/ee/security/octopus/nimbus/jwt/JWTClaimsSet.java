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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Token (JWT) claims set. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredNames()}  registered claims} of the JWT
 * specification:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>exp - Expiration Time
 *     <li>nbf - Not Before
 *     <li>iat - Issued At
 *     <li>jti - JWT ID
 * </ul>
 *
 * <p>The set may also contain custom claims; these will be serialised and
 * parsed along the registered ones.
 *
 * <p>Example JWT claims set:
 *
 * <pre>
 * {
 *   "sub"                        : "joe",
 *   "exp"                        : 1300819380,
 *   "http://example.com/is_root" : true
 * }
 * </pre>
 *
 * <p>Example usage:
 *
 * <pre>
 * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
 *     .subject("joe")
 *     .expirationTime(new Date(1300819380 * 1000l)
 *     .claim("http://example.com/is_root", true)
 *     .build();
 * </pre>
 *
 * Based on code by Vladimir Dzhuvinov and Justin Richer
 */
public final class JWTClaimsSet implements Serializable {


    private static final long serialVersionUID = 1L;


    private static final String ISSUER_CLAIM = "iss";
    private static final String SUBJECT_CLAIM = "sub";
    private static final String AUDIENCE_CLAIM = "aud";
    private static final String EXPIRATION_TIME_CLAIM = "exp";
    private static final String NOT_BEFORE_CLAIM = "nbf";
    private static final String ISSUED_AT_CLAIM = "iat";
    private static final String JWT_ID_CLAIM = "jti";


    /**
     * The registered claim names.
     */
    private static final Set<String> REGISTERED_CLAIM_NAMES;


    /*
     * Initialises the registered claim name set.
     */
    static {
        Set<String> n = new HashSet<>();

        n.add(ISSUER_CLAIM);
        n.add(SUBJECT_CLAIM);
        n.add(AUDIENCE_CLAIM);
        n.add(EXPIRATION_TIME_CLAIM);
        n.add(NOT_BEFORE_CLAIM);
        n.add(ISSUED_AT_CLAIM);
        n.add(JWT_ID_CLAIM);

        REGISTERED_CLAIM_NAMES = Collections.unmodifiableSet(n);
    }


    /**
     * Builder for constructing JSON Web Token (JWT) claims sets.
     *
     * <p>Example usage:
     *
     * <pre>
     * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
     *     .subject("joe")
     *     .expirationDate(new Date(1300819380 * 1000l)
     *     .claim("http://example.com/is_root", true)
     *     .build();
     * </pre>
     */
    public static class Builder {


        /**
         * The claims.
         */
        private final Map<String, Object> claims = new LinkedHashMap<>();


        /**
         * Creates a new builder.
         */
        public Builder() {

            // Nothing to do
        }


        /**
         * Creates a new builder with the claims from the specified
         * set.
         *
         * @param jwtClaimsSet The JWT claims set to use. Must not be
         *                     {@code null}.
         */
        public Builder(JWTClaimsSet jwtClaimsSet) {

            claims.putAll(jwtClaimsSet.claims);
        }


        /**
         * Sets the issuer ({@code iss}) claim.
         *
         * @param iss The issuer claim, {@code null} if not specified.
         * @return This builder.
         */
        public Builder issuer(String iss) {

            claims.put(ISSUER_CLAIM, iss);
            return this;
        }


        /**
         * Sets the subject ({@code sub}) claim.
         *
         * @param sub The subject claim, {@code null} if not specified.
         * @return This builder.
         */
        public Builder subject(String sub) {

            claims.put(SUBJECT_CLAIM, sub);
            return this;
        }


        /**
         * Sets the audience ({@code aud}) claim.
         *
         * @param aud The audience claim, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder audience(List<String> aud) {

            claims.put(AUDIENCE_CLAIM, aud);
            return this;
        }


        /**
         * Sets a single-valued audience ({@code aud}) claim.
         *
         * @param aud The audience claim, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder audience(String aud) {

            if (aud == null) {
                claims.put(AUDIENCE_CLAIM, null);
            } else {
                claims.put(AUDIENCE_CLAIM, Collections.singletonList(aud));
            }
            return this;
        }


        /**
         * Sets the expiration time ({@code exp}) claim.
         *
         * @param exp The expiration time, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder expirationTime(Date exp) {

            claims.put(EXPIRATION_TIME_CLAIM, exp);
            return this;
        }


        /**
         * Sets the not-before ({@code nbf}) claim.
         *
         * @param nbf The not-before claim, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder notBeforeTime(Date nbf) {

            claims.put(NOT_BEFORE_CLAIM, nbf);
            return this;
        }


        /**
         * Sets the issued-at ({@code iat}) claim.
         *
         * @param iat The issued-at claim, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder issueTime(Date iat) {

            claims.put(ISSUED_AT_CLAIM, iat);
            return this;
        }


        /**
         * Sets the JWT ID ({@code jti}) claim.
         *
         * @param jti The JWT ID claim, {@code null} if not specified.
         * @return This builder.
         */
        public Builder jwtID(String jti) {

            claims.put(JWT_ID_CLAIM, jti);
            return this;
        }


        /**
         * Sets the specified claim (registered or custom).
         *
         * @param name  The name of the claim to set. Must not be
         *              {@code null}.
         * @param value The value of the claim to set, {@code null} if
         *              not specified. Should map to a JSON entity.
         * @return This builder.
         */
        public Builder claim(String name, Object value) {

            claims.put(name, value);
            return this;
        }


        /**
         * Builds a new JWT claims set.
         *
         * @return The JWT claims set.
         */
        public JWTClaimsSet build() {

            return new JWTClaimsSet(claims);
        }
    }


    /**
     * The claims map.
     */
    private final Map<String, Object> claims = new LinkedHashMap<>();


    /**
     * Creates a new JWT claims set.
     *
     * @param claims The JWT claims set as a map. Must not be {@code null}.
     */
    private JWTClaimsSet(Map<String, Object> claims) {

        this.claims.putAll(claims);
    }


    /**
     * Gets the registered JWT claim names.
     *
     * @return The registered claim names, as a unmodifiable set.
     */
    public static Set<String> getRegisteredNames() {

        return REGISTERED_CLAIM_NAMES;
    }


    /**
     * Gets the issuer ({@code iss}) claim.
     *
     * @return The issuer claim, {@code null} if not specified.
     */
    public String getIssuer() {

        try {
            return getStringClaim(ISSUER_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the subject ({@code sub}) claim.
     *
     * @return The subject claim, {@code null} if not specified.
     */
    public String getSubject() {

        try {
            return getStringClaim(SUBJECT_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the audience ({@code aud}) claim.
     *
     * @return The audience claim, empty list if not specified.
     */
    public List<String> getAudience() {

        Object audValue = getClaim(AUDIENCE_CLAIM);

        if (audValue instanceof String) {
            // Special case
            return Collections.singletonList((String) audValue);
        }

        List<String> aud;
        try {
            aud = getStringListClaim(AUDIENCE_CLAIM);
        } catch (ParseException e) {
            return Collections.emptyList();
        }
        return aud != null ? Collections.unmodifiableList(aud) : Collections.emptyList();
    }


    /**
     * Gets the expiration time ({@code exp}) claim.
     *
     * @return The expiration time, {@code null} if not specified.
     */
    public Date getExpirationTime() {

        try {
            return getDateClaim(EXPIRATION_TIME_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the not-before ({@code nbf}) claim.
     *
     * @return The not-before claim, {@code null} if not specified.
     */
    public Date getNotBeforeTime() {

        try {
            return getDateClaim(NOT_BEFORE_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the issued-at ({@code iat}) claim.
     *
     * @return The issued-at claim, {@code null} if not specified.
     */
    public Date getIssueTime() {

        try {
            return getDateClaim(ISSUED_AT_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the JWT ID ({@code jti}) claim.
     *
     * @return The JWT ID claim, {@code null} if not specified.
     */
    public String getJWTID() {

        try {
            return getStringClaim(JWT_ID_CLAIM);
        } catch (ParseException e) {
            return null;
        }
    }


    /**
     * Gets the specified claim (registered or custom).
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     */
    public Object getClaim(String name) {

        return claims.get(name);
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link String}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public String getStringClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null || value instanceof String) {
            return (String) value;
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a String", 0);
        }
    }


    /**
     * Gets the specified claims (registered or custom) as a
     * {@link String} array.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public String[] getStringArrayClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        }

        List<?> list;

        try {
            list = (List<?>) getClaim(name);

        } catch (ClassCastException e) {
            throw new ParseException("The \"" + name + "\" claim is not a list / JSON array", 0);
        }

        String[] stringArray = new String[list.size()];

        for (int i = 0; i < stringArray.length; i++) {

            try {
                stringArray[i] = list.get(i).toString();
            } catch (ClassCastException e) {
                throw new ParseException("The \"" + name + "\" claim is not a list / JSON array of strings", 0);
            }
        }

        return stringArray;
    }


    /**
     * Gets the specified claims (registered or custom) as a
     * {@link List} list of strings.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public List<String> getStringListClaim(String name)
            throws ParseException {

        String[] stringArray = getStringArrayClaim(name);

        if (stringArray == null) {
            return null;
        }

        return Collections.unmodifiableList(Arrays.asList(stringArray));
    }


    /**
     * Gets the specified claim (registered or custom) as a
     * {@link URI}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim couldn't be parsed to a URI.
     */
    public URI getURIClaim(String name)
            throws ParseException {

        String uriString = getStringClaim(name);

        if (uriString == null) {
            return null;
        }

        try {
            return new URI(uriString);
        } catch (URISyntaxException e) {
            throw new ParseException("The \"" + name + "\" claim is not a URI: " + e.getMessage(), 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Boolean}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Boolean getBooleanClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null || value instanceof Boolean) {
            return (Boolean) value;
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a Boolean", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Integer}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Integer getIntegerClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else {
            throw new ParseException("The \"" + name + "\" claim is not an Integer", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Long}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Long getLongClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof Number) {
            return ((Number) value).longValue();
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a Number", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Date}. The claim may be represented by a Date
     * object or a number of a seconds since the Unix epoch.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Date getDateClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof Date) {
            return (Date) value;
        } else if (value instanceof Number) {
            return DateUtils.fromSecondsSinceEpoch(((Number) value).longValue());
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a Date", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Float}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Float getFloatClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof Number) {
            return ((Number) value).floatValue();
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a Float", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as
     * {@link Double}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public Double getDoubleClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof Number) {
            return ((Number) value).doubleValue();
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a Double", 0);
        }
    }


    /**
     * Gets the specified claim (registered or custom) as a
     * {@link JsonObject}.
     *
     * @param name The name of the claim. Must not be {@code null}.
     * @return The value of the claim, {@code null} if not specified.
     * @throws ParseException If the claim value is not of the required
     *                        type.
     */
    public JsonObject getJSONObjectClaim(String name)
            throws ParseException {

        Object value = getClaim(name);

        if (value == null) {
            return null;
        } else if (value instanceof JsonObject) {
            return (JsonObject) value;
        } else if (value instanceof Map) {
            return Json.createObjectBuilder((Map<String, Object>) value).build();
        } else {
            throw new ParseException("The \"" + name + "\" claim is not a JSON object or Map", 0);
        }
    }


    /**
     * Gets the claims (registered and custom).
     *
     * <p>Note that the registered claims Expiration-Time ({@code exp}),
     * Not-Before-Time ({@code nbf}) and Issued-At ({@code iat}) will be
     * returned as {@code java.util.Date} instances.
     *
     * @return The claims, as an unmodifiable map, empty map if none.
     */
    public Map<String, Object> getClaims() {

        return Collections.unmodifiableMap(claims);
    }


    /**
     * Returns the JSON object representation of the claims set. The claims
     * are serialised according to their insertion order. Claims with
     * {@code null} values are not output.
     *
     * @return The JSON object representation.
     */
    public JsonObject toJSONObject() {

        return toJSONObject(false);
    }


    /**
     * Returns the JSON object representation of the claims set. The claims
     * are serialised according to their insertion order.
     *
     * @param includeClaimsWithNullValues If {@code true} claims with
     *                                    {@code null} values will also be
     *                                    output.
     * @return The JSON object representation.
     */
    public JsonObject toJSONObject(boolean includeClaimsWithNullValues) {

        JsonObjectBuilder result = Json.createObjectBuilder();

        for (Map.Entry<String, Object> claim : claims.entrySet()) {

            if (claim.getValue() instanceof Date) {

                // Transform dates to Unix timestamps
                Date dateValue = (Date) claim.getValue();
                result.add(claim.getKey(), DateUtils.toSecondsSinceEpoch(dateValue));

            } else if (AUDIENCE_CLAIM.equals(claim.getKey())) {

                // Serialise single audience list and string
                List<String> audList = getAudience();

                if (audList != null && !audList.isEmpty()) {
                    if (audList.size() == 1) {
                        result.add(AUDIENCE_CLAIM, audList.get(0));
                    } else {
                        result.add(AUDIENCE_CLAIM, Json.createArrayBuilder(audList));
                    }
                } else if (includeClaimsWithNullValues) {
                    result.add(AUDIENCE_CLAIM, "");
                }

            } else if (claim.getValue() != null) {
                JSONObjectUtils.addValue(result, claim.getKey(), claim.getValue());
            } else if (includeClaimsWithNullValues) {
                result.addNull(claim.getKey());
            }
        }

        return result.build();
    }


    @Override
    public String toString() {

        return toJSONObject().toString();
    }


    /**
     * Parses a JSON Web Token (JWT) claims set from the specified JSON
     * object representation.
     *
     * @param json The JSON object to parse. Must not be {@code null}.
     * @return The JWT claims set.
     */
    public static JWTClaimsSet parse(JsonObject json) {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        if (json != null) {
            // Parse registered + custom params
            for (String name : json.keySet()) {

                switch (name) {
                    case ISSUER_CLAIM:

                        builder.issuer(json.getString(ISSUER_CLAIM));

                        break;
                    case SUBJECT_CLAIM:

                        builder.subject(json.getString(SUBJECT_CLAIM));

                        break;
                    case AUDIENCE_CLAIM:

                        JsonValue audValue = json.get(AUDIENCE_CLAIM);

                        if (audValue.getValueType() == JsonValue.ValueType.STRING) {
                            List<String> singleAud = new ArrayList<>();
                            singleAud.add(json.getString(AUDIENCE_CLAIM));
                            builder.audience(singleAud);
                        } else if (audValue.getValueType() == JsonValue.ValueType.ARRAY) {
                            builder.audience(JSONObjectUtils.getStringList(json, AUDIENCE_CLAIM));
                        }

                        break;
                    case EXPIRATION_TIME_CLAIM:

                        builder.expirationTime(new Date(json.getJsonNumber(EXPIRATION_TIME_CLAIM).longValue() * 1000));

                        break;
                    case NOT_BEFORE_CLAIM:

                        builder.notBeforeTime(new Date(json.getJsonNumber(NOT_BEFORE_CLAIM).longValue() * 1000));

                        break;
                    case ISSUED_AT_CLAIM:

                        builder.issueTime(new Date(json.getJsonNumber(ISSUED_AT_CLAIM).longValue() * 1000));

                        break;
                    case JWT_ID_CLAIM:

                        builder.jwtID(json.getString(JWT_ID_CLAIM));

                        break;
                    default:
                        builder.claim(name, JSONObjectUtils.getJsonValueAsObject(json.get(name)));
                        break;
                }
            }
        }
        return builder.build();
    }


    /**
     * Parses a JSON Web Token (JWT) claims set from the specified JSON
     * object string representation.
     *
     * @param value The JSON object string to parse. Must not be {@code null}.
     * @return The JWT claims set.
     * @throws ParseException If the specified JSON object string doesn't
     *                        represent a valid JWT claims set.
     */
    public static JWTClaimsSet parse(String value)
            throws ParseException {

        return parse(JSONObjectUtils.parse(value));
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JWTClaimsSet)) return false;
        JWTClaimsSet that = (JWTClaimsSet) o;
        return Objects.equals(claims, that.claims);
    }


    @Override
    public int hashCode() {
        return Objects.hash(claims);
    }
}
