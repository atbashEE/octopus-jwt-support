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


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.HeaderParameterNames;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyUse;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimNames;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.*;


/**
 * Tests JWS header parsing and serialisation.
 * <p>
 * Based on code by  Vladimir Dzhuvinov
 */
public class JWSHeaderTest {

    @Test
    public void testMinimalConstructor() {

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(header.getJWKURL()).isNull();
        Assertions.assertThat(header.getJWK()).isNull();
        Assertions.assertThat(header.getX509CertURL()).isNull();
        Assertions.assertThat(header.getX509CertSHA256Thumbprint()).isNull();
        Assertions.assertThat(header.getX509CertChain()).isNull();
        Assertions.assertThat(header.getType()).isNull();
        Assertions.assertThat(header.getContentType()).isNull();
        Assertions.assertThat(header.isBase64URLEncodePayload()).isTrue();
        Assertions.assertThat(header.getCriticalParams()).isNull();
        Assertions.assertThat(header.getCustomParameters()).isEmpty();
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
                parameter("xCustom", "+++").
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWSHeader.parse(base64URL);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getCriticalParams()).contains("iat");
        Assertions.assertThat(header.getCriticalParams()).contains("exp");
        Assertions.assertThat(header.getCriticalParams()).contains("nbf");
        Assertions.assertThat(header.getCriticalParams()).hasSize(3);
        Assertions.assertThat(header.getContentType()).isEqualTo("application/json");
        Assertions.assertThat(header.getJWKURL()).isEqualTo(new URI("https://example.com/jku.json"));
        Assertions.assertThat(header.getKeyID()).isEqualTo("1234");
        Assertions.assertThat(header.isBase64URLEncodePayload()).isTrue();

        jwk = (RSAKey) header.getJWK();
        Assertions.assertThat(jwk).isNotNull();
        Assertions.assertThat(jwk.getModulus()).isEqualTo(new Base64URLValue("abc123"));
        Assertions.assertThat(jwk.getPublicExponent()).isEqualTo(new Base64URLValue("def456"));
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        Assertions.assertThat(jwk.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("1234");

        Assertions.assertThat(header.getX509CertURL()).isEqualTo(new URI("https://example/cert.b64"));
        Assertions.assertThat(header.getX509CertSHA256Thumbprint()).isEqualTo(new Base64URLValue("789asd"));

        certChain = header.getX509CertChain();
        Assertions.assertThat(certChain).hasSize(3);
        Assertions.assertThat(certChain.get(0)).isEqualTo(new Base64Value("asd"));
        Assertions.assertThat(certChain.get(1)).isEqualTo(new Base64Value("fgh"));
        Assertions.assertThat(certChain.get(2)).isEqualTo(new Base64Value("jkl"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        Assertions.assertThat(header.getIncludedParameters()).contains("alg");
        Assertions.assertThat(header.getIncludedParameters()).contains("typ");
        Assertions.assertThat(header.getIncludedParameters()).contains("cty");
        Assertions.assertThat(header.getIncludedParameters()).contains("crit");
        Assertions.assertThat(header.getIncludedParameters()).contains("jku");
        Assertions.assertThat(header.getIncludedParameters()).contains("jwk");
        Assertions.assertThat(header.getIncludedParameters()).contains("kid");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5u");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5c");
        Assertions.assertThat(header.getIncludedParameters()).contains("xCustom");
        Assertions.assertThat(header.getIncludedParameters()).hasSize(11);

    }

    @Test
    public void testCopyConstructor()
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
                parameter("xCustom", "+++").
                build();


        header = new JWSHeader(header);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getCriticalParams()).contains("iat");
        Assertions.assertThat(header.getCriticalParams()).contains("exp");
        Assertions.assertThat(header.getCriticalParams()).contains("nbf");
        Assertions.assertThat(header.getCriticalParams()).hasSize(3);
        Assertions.assertThat(header.getContentType()).isEqualTo("application/json");
        Assertions.assertThat(header.getJWKURL()).isEqualTo(new URI("https://example.com/jku.json"));
        Assertions.assertThat(header.getKeyID()).isEqualTo("1234");

        jwk = (RSAKey) header.getJWK();
        Assertions.assertThat(jwk).isNotNull();
        Assertions.assertThat(jwk.getModulus()).isEqualTo(new Base64URLValue("abc123"));
        Assertions.assertThat(jwk.getPublicExponent()).isEqualTo(new Base64URLValue("def456"));
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        Assertions.assertThat(jwk.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("1234");

        Assertions.assertThat(header.getX509CertURL()).isEqualTo(new URI("https://example/cert.b64"));
        Assertions.assertThat(header.getX509CertSHA256Thumbprint()).isEqualTo(new Base64URLValue("789asd"));

        certChain = header.getX509CertChain();
        Assertions.assertThat(certChain.size()).isEqualTo(3);
        Assertions.assertThat(certChain.get(0)).isEqualTo(new Base64Value("asd"));
        Assertions.assertThat(certChain.get(1)).isEqualTo(new Base64Value("fgh"));
        Assertions.assertThat(certChain.get(2)).isEqualTo(new Base64Value("jkl"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

    }

    @Test
    public void testWithParameters()
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

        Map<String, Object> parameters = new HashMap<>();
        parameters.put(HeaderParameterNames.TYPE, new JOSEObjectType("JWT"));
        parameters.put(HeaderParameterNames.CONTENT_TYPE, "application/json");
        parameters.put(HeaderParameterNames.CRITICAL, crit);
        parameters.put(HeaderParameterNames.JWK_SET_URL, new URI("https://example.com/jku.json"));
        parameters.put(HeaderParameterNames.JSON_WEB_KEY, jwk);
        parameters.put(HeaderParameterNames.X_509_URL, new URI("https://example/cert.b64"));
        parameters.put("x5t256", new Base64URLValue("789asd"));
        parameters.put("x5c", certChain);
        parameters.put(HeaderParameterNames.KEY_ID, "1234");
        parameters.put("xCustom", "+++");
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                parameters(parameters).
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWSHeader.parse(base64URL);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getCriticalParams()).contains("iat");
        Assertions.assertThat(header.getCriticalParams()).contains("exp");
        Assertions.assertThat(header.getCriticalParams()).contains("nbf");
        Assertions.assertThat(header.getCriticalParams()).hasSize(3);
        Assertions.assertThat(header.getContentType()).isEqualTo("application/json");
        Assertions.assertThat(header.getJWKURL()).isEqualTo(new URI("https://example.com/jku.json"));
        Assertions.assertThat(header.getKeyID()).isEqualTo("1234");
        Assertions.assertThat(header.isBase64URLEncodePayload()).isTrue();

        jwk = (RSAKey) header.getJWK();
        Assertions.assertThat(jwk).isNotNull();
        Assertions.assertThat(jwk.getModulus()).isEqualTo(new Base64URLValue("abc123"));
        Assertions.assertThat(jwk.getPublicExponent()).isEqualTo(new Base64URLValue("def456"));
        Assertions.assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        Assertions.assertThat(jwk.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(jwk.getKeyID()).isEqualTo("1234");

        Assertions.assertThat(header.getX509CertURL()).isEqualTo(new URI("https://example/cert.b64"));
        Assertions.assertThat(header.getX509CertSHA256Thumbprint()).isEqualTo(new Base64URLValue("789asd"));

        certChain = header.getX509CertChain();
        Assertions.assertThat(certChain).hasSize(3);
        Assertions.assertThat(certChain.get(0)).isEqualTo(new Base64Value("asd"));
        Assertions.assertThat(certChain.get(1)).isEqualTo(new Base64Value("fgh"));
        Assertions.assertThat(certChain.get(2)).isEqualTo(new Base64Value("jkl"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        Assertions.assertThat(header.getIncludedParameters()).contains("alg");
        Assertions.assertThat(header.getIncludedParameters()).contains("typ");
        Assertions.assertThat(header.getIncludedParameters()).contains("cty");
        Assertions.assertThat(header.getIncludedParameters()).contains("crit");
        Assertions.assertThat(header.getIncludedParameters()).contains("jku");
        Assertions.assertThat(header.getIncludedParameters()).contains("jwk");
        Assertions.assertThat(header.getIncludedParameters()).contains("kid");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5u");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5c");
        Assertions.assertThat(header.getIncludedParameters()).contains("xCustom");
        Assertions.assertThat(header.getIncludedParameters()).hasSize(11);
    }

    @Test
    public void testParseJSONText()
            throws Exception {

        // Example header from JWS spec

        String data = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

        JWSHeader h = JWSHeader.parse(data);

        Assertions.assertThat(h).isNotNull();

        Assertions.assertThat(h.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(h.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(h.getContentType()).isNull();

        Assertions.assertThat(h.getIncludedParameters()).contains("alg");
        Assertions.assertThat(h.getIncludedParameters()).contains("typ");
        Assertions.assertThat(h.getIncludedParameters()).hasSize(2);
    }

    @Test
    public void testParseBase64URLText()
            throws Exception {

        // Example header from JWS spec

        Base64URLValue in = new Base64URLValue("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        JWSHeader header = JWSHeader.parse(in);

        Assertions.assertThat(header.toBase64URL()).isEqualTo(in);

        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(header.getContentType()).isNull();
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

        Assertions.assertThat(header.getCriticalParams().size()).isEqualTo(3);

        Base64URLValue b64url = header.toBase64URL();

        // Parse back
        header = JWSHeader.parse(b64url);

        crit = header.getCriticalParams();

        Assertions.assertThat(crit).containsOnly("iat", "exp", "nbf");

    }

    @Test
    public void testRejectNone() {

        Assertions.assertThatThrownBy(() -> new JWSHeader(new JWSAlgorithm("none")))
                .isInstanceOf(IllegalArgumentException.class);

    }

    @Test
    public void testBuilder()
            throws Exception {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");

        AtbashKey publicKey = Filters.findPublicKey(keys);
        RSAKey jwk = new RSAKey.Builder(publicKey).build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                type(JOSEObjectType.JOSE).
                contentType("application/json").
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                jwkURL(new URI("http://example.com/jwk.json")).
                jwk(jwk).
                x509CertURL(new URI("http://example.com/cert.pem")).
                x509CertSHA256Thumbprint(new Base64URLValue("abc256")).
                x509CertChain(Arrays.asList(new Base64Value("abc"), new Base64Value("def"))).
                keyID("123").
                parameter("exp", 123).
                parameter("nbf", 456).
                build();

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(header.getType()).isEqualTo(JOSEObjectType.JOSE);
        Assertions.assertThat(header.getContentType()).isEqualTo("application/json");

        Assertions.assertThat(header.getCriticalParams()).containsOnly("exp", "nbf");

        Assertions.assertThat(header.getJWKURL().toString()).isEqualTo("http://example.com/jwk.json");
        Assertions.assertThat(((RSAKey) header.getJWK()).toRSAPublicKey()).isEqualTo(publicKey.getKey());
        Assertions.assertThat(header.getX509CertURL().toString()).isEqualTo("http://example.com/cert.pem");
        Assertions.assertThat(header.getX509CertSHA256Thumbprint().toString()).isEqualTo("abc256");
        Assertions.assertThat(header.getX509CertChain().get(0).toString()).isEqualTo("abc");
        Assertions.assertThat(header.getX509CertChain().get(1).toString()).isEqualTo("def");
        Assertions.assertThat(header.getX509CertChain().size()).isEqualTo(2);
        Assertions.assertThat(header.getKeyID()).isEqualTo("123");
        Assertions.assertThat(header.getCustomParameter("exp")).isEqualTo(123);
        Assertions.assertThat(header.getCustomParameter("nbf")).isEqualTo(456);
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(2);
        Assertions.assertThat(header.getParsedBase64URL()).isNull();

        Assertions.assertThat(header.getIncludedParameters()).containsOnly("alg", "typ", "cty", "crit", "jku", "jwk", "x5u", "x5t#S256", "x5c", "kid", "exp", "nbf");
    }

    @Test
    public void testB64_builder() throws ParseException {

        // Builder
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .base64URLEncodePayload(false)
                .criticalParams(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD))
                .build();

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.isBase64URLEncodePayload()).isFalse();

        Assertions.assertThat(header.getCriticalParams()).containsOnly("b64");

        Assertions.assertThat(header.getIncludedParameters())
                .containsOnly("alg", "b64", "crit");

        // Builder copy constructor
        header = new JWSHeader.Builder(header)
                .build();

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.isBase64URLEncodePayload()).isFalse();

        Assertions.assertThat(header.getCriticalParams()).containsOnly("b64");

        Assertions.assertThat(header.getIncludedParameters())
                .containsOnly("alg", "b64", "crit");

        // Serialisation
        JsonObject o = header.toJSONObject().build();
        Assertions.assertThat(JSONObjectUtils.getJsonValueAsObject(o.get(HeaderParameterNames.ALGORITHM)).toString()).isEqualTo(JWSAlgorithm.RS256.getName());
        Assertions.assertThat(o.get(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD).toString()).isEqualTo("false");

        Assertions.assertThat(JSONObjectUtils.getStringList(o, HeaderParameterNames.CRITICAL)).containsOnly("b64");
        Assertions.assertThat(o).hasSize(3);


        Base64URLValue base64URL = header.toBase64URL();

        // Parse
        header = JWSHeader.parse(base64URL);
        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        Assertions.assertThat(header.isBase64URLEncodePayload()).isFalse();
        Assertions.assertThat(header.getCriticalParams()).containsOnly("b64");

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

    }

    @Test
    public void testB64_parseExampleHeader() throws ParseException {

        String s = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        JWSHeader header = JWSHeader.parse(new Base64URLValue(s));

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(header.isBase64URLEncodePayload()).isFalse();
        Assertions.assertThat(header.getCriticalParams()).containsOnly("b64");


        Assertions.assertThat(header.getIncludedParameters()).containsOnly("alg", "b64", "crit");
    }

    @Test
    public void testBuilderWithCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put(JWKIdentifiers.X_COORD, "1");
        customParams.put(JWKIdentifiers.Y_COORD, "2");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                parameters(customParams).
                build();

        Assertions.assertThat(header.getCustomParameter("x")).isEqualTo("1");
        Assertions.assertThat(header.getCustomParameter("y")).isEqualTo("2");
        Assertions.assertThat(header.getCustomParameters()).hasSize(2);
    }

    @Test
    public void testImmutableCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put(JWKIdentifiers.X_COORD, "1");
        customParams.put(JWKIdentifiers.Y_COORD, "2");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                parameters(customParams).
                build();

        Assertions.assertThatThrownBy(() -> header.getCustomParameters().put("x", "3"))
                .isInstanceOf(UnsupportedOperationException.class);

    }

    @Test
    public void testImmutableCritHeaders() {

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                build();

        Assertions.assertThatThrownBy(() -> header.getCriticalParams().remove("exp"))
                .isInstanceOf(UnsupportedOperationException.class);

    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
    public void testParseCustomParamListOfStrings()
            throws ParseException {

        String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

        JWSHeader header = JWSHeader.parse(json);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);

        List<String> audList = (List<String>) header.getCustomParameter("aud");
        Assertions.assertThat(audList).containsExactly("a", "b");


        List<String> testList = (List<String>) header.getCustomParameter("test");
        Assertions.assertThat(testList).containsExactly("a", "b");

    }

    @Test
    // https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
    public void testSetCustomParamListOfStrings() {

        List<String> audList = new LinkedList<>();
        audList.add("a");
        audList.add("b");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .parameter(JWTClaimNames.AUDIENCE, audList)
                .build();

        Assertions.assertThat(header.toJSONObject().build().toString()).contains("\"aud\":[\"a\",\"b\"]");
    }

    @Test
    // iss #208
    public void testHeaderParameterAsJSONObject()
            throws Exception {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("key", "value");

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .parameter("prm", builder.build())
                .build();

        JsonObject jsonObject = (JsonObject) header.getCustomParameter("prm");

        Assertions.assertThat(jsonObject.keySet()).containsOnly("key");


        JsonObject headerJSONObject = header.toJSONObject().build();
        Assertions.assertThat(headerJSONObject.getString(HeaderParameterNames.ALGORITHM)).isEqualTo("HS256");
        jsonObject = (JsonObject) headerJSONObject.get("prm");
        Assertions.assertThat(jsonObject.getString("key")).isEqualTo("value");
        Assertions.assertThat(jsonObject.size()).isEqualTo(1);
        Assertions.assertThat(headerJSONObject.size()).isEqualTo(2);

        Base64URLValue encodedHeader = header.toBase64URL();

        header = JWSHeader.parse(encodedHeader);

        jsonObject = (JsonObject) header.getCustomParameter("prm");
        Assertions.assertThat(jsonObject.getString("key")).isEqualTo("value");
        Assertions.assertThat(jsonObject).hasSize(1);

        headerJSONObject = header.toJSONObject().build();
        Assertions.assertThat(headerJSONObject.getString(HeaderParameterNames.ALGORITHM)).isEqualTo("HS256");
        jsonObject = (JsonObject) headerJSONObject.get("prm");
        Assertions.assertThat(jsonObject.getString("key")).isEqualTo("value");
        Assertions.assertThat(jsonObject).hasSize(1);
        Assertions.assertThat(headerJSONObject).hasSize(2);
    }

    @Test
    // iss #282
    public void testParseHeaderWithNullParamValue()
            throws Exception {

        String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6bnVsbH0";

        JsonObject jsonObject = JSONObjectUtils.parse(new Base64URLValue(header).decodeToString());

        Assertions.assertThat(jsonObject.getString(HeaderParameterNames.ALGORITHM)).isEqualTo("HS256");
        Assertions.assertThat(jsonObject.getString(HeaderParameterNames.TYPE)).isEqualTo("JWT");
        Assertions.assertThat(jsonObject.get("cty").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        Assertions.assertThat(jsonObject).hasSize(3);

        JWSHeader jwsHeader = JWSHeader.parse(new Base64URLValue(header));

        Assertions.assertThat(jwsHeader.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        Assertions.assertThat(jwsHeader.getType()).isEqualTo(JOSEObjectType.JWT);
        Assertions.assertThat(jwsHeader.getContentType()).isNull();
        Assertions.assertThat(jwsHeader.toJSONObject().build()).hasSize(2);
    }

    @Test
    // iss #333
    public void testParseHeaderWithNullTyp()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, "HS256");
        builder.addNull(HeaderParameterNames.TYPE);
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(2);

        Header header = JWSHeader.parse(jsonObject);
        Assertions.assertThat(header.getType()).isNull();
    }

    @Test
    // iss #334
    public void testParseHeaderWithNullCrit()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, "HS256");
        builder.addNull("crit");
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(2);

        Header header = JWSHeader.parse(jsonObject);
        Assertions.assertThat(header.getCriticalParams()).isEmpty();
    }

    @Test
    public void testParseHeaderWithNullJWK()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, "HS256");
        builder.addNull(HeaderParameterNames.JSON_WEB_KEY);
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(2);

        JWSHeader header = JWSHeader.parse(jsonObject);
        Assertions.assertThat(header.getJWK()).isNull();
    }

    @Test
    public void getRegisteredParameterNames() {
        Assertions.assertThat(JWSHeader.getRegisteredParameterNames()).hasSize(10);
    }

    @Test
    public void testParameterJKU() {

        String uriStr = "http://localhost/something";
        URI jku = URI.create(uriStr);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .parameter(HeaderParameterNames.JWK_SET_URL, jku)
                .build();

        Assertions.assertThat(header.getJWKURL().toASCIIString()).isEqualTo(uriStr);
    }

    @Test
    public void testParseHeaderWithNonPublicJWK() throws JOSEException {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        JsonObjectBuilder jsonObjectBuilder = header.toJSONObject();

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid", 2048);
        List<AtbashKey> privateKey = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        List<AtbashKey> publicKey = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);

        RSAKey rsaKey = new RSAKey.Builder(publicKey.get(0))
                .privateKey((RSAPrivateKey) privateKey.get(0).getKey())
                .keyID("kid")
                .build();

        jsonObjectBuilder.add("jwk", rsaKey.toJSONObject().build());

        Assertions.assertThatThrownBy(
                        () -> JWSHeader.parse(jsonObjectBuilder.build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Non-public key in jwk header parameter");

    }
}

