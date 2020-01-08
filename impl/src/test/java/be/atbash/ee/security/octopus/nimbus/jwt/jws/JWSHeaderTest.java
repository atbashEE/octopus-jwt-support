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
package be.atbash.ee.security.octopus.nimbus.jwt.jws;


import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyUse;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.net.URI;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-04
 */
public class JWSHeaderTest {

    @Test
    public void testMinimalConstructor() {

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(header.getJWKURL()).isNull();
        assertThat(header.getJWK()).isNull();
        assertThat(header.getX509CertURL()).isNull();
        assertThat(header.getX509CertSHA256Thumbprint()).isNull();
        assertThat(header.getX509CertChain()).isNull();
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCriticalParams()).isNull();
        assertThat(header.getCustomParams()).isEmpty();
    }


    @Test
    public void testSerializeAndParse()
            throws Exception {

        Set<String> crit = new HashSet<>();
        crit.add("iat");
        crit.add("exp");
        crit.add("nbf");

        Base64URLValue mod = new Base64URLValue("abc123");
        Base64URLValue exp = new Base64URLValue("def456");
        KeyUse use = KeyUse.ENCRYPTION;
        String kid = "1234";

        RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA_OAEP_256).keyID(kid).build();

        List<Base64Value> certChain = new LinkedList<>();
        certChain.add(new Base64Value("asd"));
        certChain.add(new Base64Value("fgh"));
        certChain.add(new Base64Value("jkl"));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                type(new JOSEObjectType("JWT")).
                contentType("application/json").
                criticalParams(crit).
                jwkURL(new URI("https://example.com/jku.json")).
                jwk(jwk).
                x509CertURL(new URI("https://example/cert.b64")).
                x509CertSHA256Thumbprint(new Base64URLValue("789asd")).
                x509CertChain(certChain).
                keyID("1234").
                customParam("xCustom", "+++").
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWSHeader.parse(base64URL);

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getCriticalParams()).contains("iat");
        assertThat(header.getCriticalParams()).contains("exp");
        assertThat(header.getCriticalParams()).contains("nbf");
        assertThat(header.getCriticalParams()).hasSize(3);
        assertThat(header.getContentType()).isEqualTo("application/json");
        assertThat(header.getJWKURL()).isEqualTo(new URI("https://example.com/jku.json"));
        assertThat(header.getKeyID()).isEqualTo("1234");

        jwk = (RSAKey) header.getJWK();
        assertThat(jwk).isNotNull();
        assertThat(jwk.getModulus()).isEqualTo(new Base64URLValue("abc123"));
        assertThat(jwk.getPublicExponent()).isEqualTo(new Base64URLValue("def456"));
        assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(jwk.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(jwk.getKeyID()).isEqualTo("1234");

        assertThat(header.getX509CertURL()).isEqualTo(new URI("https://example/cert.b64"));
        assertThat(header.getX509CertSHA256Thumbprint()).isEqualTo(new Base64URLValue("789asd"));

        certChain = header.getX509CertChain();
        assertThat(certChain).hasSize(3);
        assertThat(certChain.get(0)).isEqualTo(new Base64Value("asd"));
        assertThat(certChain.get(1)).isEqualTo(new Base64Value("fgh"));
        assertThat(certChain.get(2)).isEqualTo(new Base64Value("jkl"));

        assertThat(header.getCustomParam("xCustom")).isEqualTo("+++");
        assertThat(header.getCustomParams().size()).isEqualTo(1);

        assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        assertThat(header.getIncludedParams()).contains("alg");
        assertThat(header.getIncludedParams()).contains("typ");
        assertThat(header.getIncludedParams()).contains("cty");
        assertThat(header.getIncludedParams()).contains("crit");
        assertThat(header.getIncludedParams()).contains("jku");
        assertThat(header.getIncludedParams()).contains("jwk");
        assertThat(header.getIncludedParams()).contains("kid");
        assertThat(header.getIncludedParams()).contains("x5u");
        assertThat(header.getIncludedParams()).contains("x5c");
        assertThat(header.getIncludedParams()).contains("xCustom");
        assertThat(header.getIncludedParams()).hasSize(11);

        // Test copy constructor
        header = new JWSHeader(header);

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getCriticalParams()).contains("iat");
        assertThat(header.getCriticalParams()).contains("exp");
        assertThat(header.getCriticalParams()).contains("nbf");
        assertThat(header.getCriticalParams()).hasSize(3);
        assertThat(header.getContentType()).isEqualTo("application/json");
        assertThat(header.getJWKURL()).isEqualTo(new URI("https://example.com/jku.json"));
        assertThat(header.getKeyID()).isEqualTo("1234");

        jwk = (RSAKey) header.getJWK();
        assertThat(jwk).isNotNull();
        assertThat(jwk.getModulus()).isEqualTo(new Base64URLValue("abc123"));
        assertThat(jwk.getPublicExponent()).isEqualTo(new Base64URLValue("def456"));
        assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(jwk.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(jwk.getKeyID()).isEqualTo("1234");

        assertThat(header.getX509CertURL()).isEqualTo(new URI("https://example/cert.b64"));
        assertThat(header.getX509CertSHA256Thumbprint()).isEqualTo(new Base64URLValue("789asd"));

        certChain = header.getX509CertChain();
        assertThat(certChain.size()).isEqualTo(3);
        assertThat(certChain.get(0)).isEqualTo(new Base64Value("asd"));
        assertThat(certChain.get(1)).isEqualTo(new Base64Value("fgh"));
        assertThat(certChain.get(2)).isEqualTo(new Base64Value("jkl"));

        assertThat(header.getCustomParam("xCustom")).isEqualTo("+++");
        assertThat(header.getCustomParams().size()).isEqualTo(1);

        assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);
    }

    @Test
    public void testParseJSONText()
            throws Exception {

        // Example header from JWS spec

        String data = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

        JWSHeader h = JWSHeader.parse(data);

        assertThat(h).isNotNull();

        assertThat(h.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(h.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(h.getContentType()).isNull();

        assertThat(h.getIncludedParams()).contains("alg");
        assertThat(h.getIncludedParams()).contains("typ");
        assertThat(h.getIncludedParams()).hasSize(2);
    }

    @Test
    public void testParseBase64URLText()
            throws Exception {

        // Example header from JWS spec

        Base64URLValue in = new Base64URLValue("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        JWSHeader header = JWSHeader.parse(in);

        assertThat(header.toBase64URL()).isEqualTo(in);

        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(header.getContentType()).isNull();
    }

    @Test
    public void testCrit()
            throws Exception {

        Set<String> crit = new HashSet<>();
        crit.add("iat");
        crit.add("exp");
        crit.add("nbf");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                criticalParams(crit).
                build();

        assertThat(header.getCriticalParams().size()).isEqualTo(3);

        Base64URLValue b64url = header.toBase64URL();

        // Parse back
        header = JWSHeader.parse(b64url);

        crit = header.getCriticalParams();

        assertThat(crit).containsOnly("iat", "exp", "nbf");

    }

    @Test
    public void testRejectNone() {

        Assertions.assertThrows(IllegalArgumentException.class, () -> new JWSHeader(new JWSAlgorithm("none")));

    }

    @Test
    public void testBuilder()
            throws Exception {

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                type(JOSEObjectType.JOSE).
                contentType("application/json").
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                jwkURL(new URI("http://example.com/jwk.json")).
                jwk(new OctetSequenceKey.Builder(new Base64URLValue("xyz")).build()).
                x509CertURL(new URI("http://example.com/cert.pem")).
                x509CertSHA256Thumbprint(new Base64URLValue("abc256")).
                x509CertChain(Arrays.asList(new Base64Value("abc"), new Base64Value("def"))).
                keyID("123").
                customParam("exp", 123).
                customParam("nbf", 456).
                build();

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(header.getType()).isEqualTo(JOSEObjectType.JOSE);
        assertThat(header.getContentType()).isEqualTo("application/json");

        assertThat(header.getCriticalParams()).containsOnly("exp", "nbf");

        assertThat(header.getJWKURL().toString()).isEqualTo("http://example.com/jwk.json");
        assertThat(((OctetSequenceKey) header.getJWK()).getKeyValue().toString()).isEqualTo("xyz");
        assertThat(header.getX509CertURL().toString()).isEqualTo("http://example.com/cert.pem");
        assertThat(header.getX509CertSHA256Thumbprint().toString()).isEqualTo("abc256");
        assertThat(header.getX509CertChain().get(0).toString()).isEqualTo("abc");
        assertThat(header.getX509CertChain().get(1).toString()).isEqualTo("def");
        assertThat(header.getX509CertChain().size()).isEqualTo(2);
        assertThat(header.getKeyID()).isEqualTo("123");
        assertThat(header.getCustomParam("exp")).isEqualTo(123);
        assertThat(header.getCustomParam("nbf")).isEqualTo(456);
        assertThat(header.getCustomParams().size()).isEqualTo(2);
        assertThat(header.getParsedBase64URL()).isNull();

        assertThat(header.getIncludedParams()).containsOnly("alg", "typ", "cty", "crit", "jku", "jwk", "x5u", "x5t#S256", "x5c", "kid", "exp", "nbf");
    }

    @Test
    public void testBuilderWithCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put("x", "1");
        customParams.put("y", "2");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                customParams(customParams).
                build();

        assertThat(header.getCustomParam("x")).isEqualTo("1");
        assertThat(header.getCustomParam("y")).isEqualTo("2");
        assertThat(header.getCustomParams().size()).isEqualTo(2);
    }

    @Test
    public void testImmutableCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put("x", "1");
        customParams.put("y", "2");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                customParams(customParams).
                build();

        Assertions.assertThrows(UnsupportedOperationException.class, () -> header.getCustomParams().put("x", "3"));

    }

    @Test
    public void testImmutableCritHeaders() {

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                build();

        Assertions.assertThrows(UnsupportedOperationException.class, () -> header.getCriticalParams().remove("exp"));
    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
    public void testParseCustomParamListOfStrings()
            throws ParseException {

        String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

        JWSHeader header = JWSHeader.parse(json);

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);

        List<?> audList = (List) header.getCustomParam("aud");
        assertThat(audList.get(0)).isEqualTo("a");
        assertThat(audList.get(1)).isEqualTo("b");
        assertThat(audList.size()).isEqualTo(2);

        List<?> testList = (List) header.getCustomParam("test");
        assertThat(testList.get(0)).isEqualTo("a");
        assertThat(testList.get(1)).isEqualTo("b");
        assertThat(testList.size()).isEqualTo(2);
    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
    public void testSetCustomParamListOfStrings() {

        List<String> audList = new LinkedList<>();
        audList.add("a");
        audList.add("b");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .customParam("aud", audList)
                .build();

        assertThat(header.toJSONObject().build().toString()).contains("\"aud\":[\"a\",\"b\"]");
    }

    @Test
    // iss #208
    public void testHeaderParameterAsJSONObject()
            throws Exception {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("key", "value");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .customParam("prm", builder.build())
                .build();

        JsonObject jsonObject = (JsonObject) header.getCustomParam("prm");

        assertThat(jsonObject.keySet()).containsOnly("key");


        JsonObject headerJSONObject = header.toJSONObject().build();
        assertThat(headerJSONObject.getString("alg")).isEqualTo("HS256");
        jsonObject = (JsonObject) headerJSONObject.get("prm");
        assertThat(jsonObject.getString("key")).isEqualTo("value");
        assertThat(jsonObject.size()).isEqualTo(1);
        assertThat(headerJSONObject.size()).isEqualTo(2);

        Base64URLValue encodedHeader = header.toBase64URL();

        header = JWSHeader.parse(encodedHeader);

        jsonObject = (JsonObject) header.getCustomParam("prm");
        assertThat(jsonObject.getString("key")).isEqualTo("value");
        assertThat(jsonObject).hasSize(1);

        headerJSONObject = header.toJSONObject().build();
        assertThat(headerJSONObject.getString("alg")).isEqualTo("HS256");
        jsonObject = (JsonObject) headerJSONObject.get("prm");
        assertThat(jsonObject.getString("key")).isEqualTo("value");
        assertThat(jsonObject).hasSize(1);
        assertThat(headerJSONObject).hasSize(2);
    }

    @Test
    // iss #282
    public void testParseHeaderWithNullParamValue()
            throws Exception {

        String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6bnVsbH0";

        JsonObject jsonObject = JSONObjectUtils.parse(new Base64URLValue(header).decodeToString());

        assertThat(jsonObject.getString("alg")).isEqualTo("HS256");
        assertThat(jsonObject.getString("typ")).isEqualTo("JWT");
        assertThat(jsonObject.get("cty").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(jsonObject).hasSize(3);

        JWSHeader jwsHeader = JWSHeader.parse(new Base64URLValue(header));

        assertThat(jwsHeader.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(jwsHeader.getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(jwsHeader.getContentType()).isNull();
        assertThat(jwsHeader.toJSONObject().build()).hasSize(2);
    }

    @Test
    // iss #333
    public void testParseHeaderWithNullTyp()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", "HS256");
        builder.addNull("typ");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(2);

        Header header = JWSHeader.parse(jsonObject);
        assertThat(header.getType()).isNull();
    }

    @Test
    // iss #334
    public void testParseHeaderWithNullCrit()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", "HS256");
        builder.addNull("crit");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(2);

        Header header = JWSHeader.parse(jsonObject);
        assertThat(header.getCriticalParams()).isEmpty();
    }

    @Test
    public void testParseHeaderWithNullJWK()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", "HS256");
        builder.addNull("jwk");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(2);

        JWSHeader header = JWSHeader.parse(jsonObject);
        assertThat(header.getJWK()).isNull();
    }
}

