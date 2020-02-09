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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;

import be.atbash.ee.security.octopus.nimbus.jose.CompressionAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jose.Header;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEObjectType;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyUse;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetSequenceKey;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests JWE header parsing and serialisation.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class JWEHeaderTest {


    @Test
    public void testMinimalConstructor() {

        JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

        assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
        assertThat(header.getJWKURL()).isNull();
        assertThat(header.getJWK()).isNull();
        assertThat(header.getX509CertURL()).isNull();
        assertThat(header.getX509CertSHA256Thumbprint()).isNull();
        assertThat(header.getX509CertChain()).isNull();
        assertThat(header.getType()).isNull();
        assertThat(header.getContentType()).isNull();
        assertThat(header.getCriticalParams()).isNull();
        assertThat(header.getEphemeralPublicKey()).isNull();
        assertThat(header.getCompressionAlgorithm()).isNull();
        assertThat(header.getAgreementPartyUInfo()).isNull();
        assertThat(header.getAgreementPartyVInfo()).isNull();
        assertThat(header.getPBES2Salt()).isNull();
        assertThat(header.getIV()).isNull();
        assertThat(header.getAuthTag()).isNull();
        assertThat(header.getPBES2Count()).isEqualTo(0);
        assertThat(header.getCustomParameters()).isEmpty();
    }

    @Test
    public void testSerializeAndParse()
            throws Exception {

        Base64URLValue mod = new Base64URLValue("abc123");
        Base64URLValue exp = new Base64URLValue("def456");
        KeyUse use = KeyUse.ENCRYPTION;
        String kid = "1234";

        RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA_OAEP_256).keyID(kid).build();

        List<Base64Value> certChain = new LinkedList<>();
        certChain.add(new Base64Value("asd"));
        certChain.add(new Base64Value("fgh"));
        certChain.add(new Base64Value("jkl"));

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).
                type(new JOSEObjectType("JWT")).
                compressionAlgorithm(CompressionAlgorithm.DEF).
                jwkURL(new URI("https://example.com/jku.json")).
                jwk(jwk).
                x509CertURL(new URI("https://example/cert.b64")).
                x509CertSHA256Thumbprint(new Base64URLValue("789asd")).
                x509CertChain(certChain).
                keyID("1234").
                agreementPartyUInfo(new Base64URLValue("abc")).
                agreementPartyVInfo(new Base64URLValue("xyz")).
                pbes2Salt(new Base64URLValue("omg")).
                pbes2Count(1000).
                iv(new Base64URLValue("101010")).
                authTag(new Base64URLValue("202020")).
                parameter("xCustom", "+++").
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWEHeader.parse(base64URL);

        assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        assertThat(header.getPBES2Count()).isEqualTo(1000);

        assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);

        assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        assertThat(header.getIncludedParameters()).contains("alg");
        assertThat(header.getIncludedParameters()).contains("typ");
        assertThat(header.getIncludedParameters()).contains("enc");
        assertThat(header.getIncludedParameters()).contains("zip");
        assertThat(header.getIncludedParameters()).contains("jku");
        assertThat(header.getIncludedParameters()).contains("jwk");
        assertThat(header.getIncludedParameters()).contains("kid");
        assertThat(header.getIncludedParameters()).contains("x5u");
        assertThat(header.getIncludedParameters()).contains("x5c");
        assertThat(header.getIncludedParameters()).contains("apu");
        assertThat(header.getIncludedParameters()).contains("apv");
        assertThat(header.getIncludedParameters()).contains("p2s");
        assertThat(header.getIncludedParameters()).contains("p2c");
        assertThat(header.getIncludedParameters()).contains("iv");
        assertThat(header.getIncludedParameters()).contains("tag");
        assertThat(header.getIncludedParameters()).contains("xCustom");
        assertThat(header.getIncludedParameters()).hasSize(17);

        // Test copy constructor
        header = new JWEHeader(header);

        assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        assertThat(header.getPBES2Count()).isEqualTo(1000);

        assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);

        assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);
    }

    @Test
    public void testWithParameters()
            throws Exception {

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
        parameters.put("typ", new JOSEObjectType("JWT"));
        parameters.put("zip", CompressionAlgorithm.DEF);
        parameters.put("jku", new URI("https://example.com/jku.json"));
        parameters.put("jwk", jwk);
        parameters.put("x5u", new URI("https://example/cert.b64"));
        parameters.put("x5t256", new Base64URLValue("789asd"));
        parameters.put("x5c", certChain);
        parameters.put("kid", "1234");
        parameters.put("apu", new Base64URLValue("abc"));
        parameters.put("apv", new Base64URLValue("xyz"));
        parameters.put("p2s", new Base64URLValue("omg"));
        parameters.put("p2c", 1000);
        parameters.put("iv", new Base64URLValue("101010"));
        parameters.put("tag", new Base64URLValue("202020"));
        parameters.put("xCustom", "+++");

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).
                parameters(parameters).
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWEHeader.parse(base64URL);

        assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        assertThat(header.getPBES2Count()).isEqualTo(1000);

        assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        assertThat(header.getCustomParameters().size()).isEqualTo(1);

        assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        assertThat(header.getIncludedParameters()).contains("alg");
        assertThat(header.getIncludedParameters()).contains("typ");
        assertThat(header.getIncludedParameters()).contains("enc");
        assertThat(header.getIncludedParameters()).contains("zip");
        assertThat(header.getIncludedParameters()).contains("jku");
        assertThat(header.getIncludedParameters()).contains("jwk");
        assertThat(header.getIncludedParameters()).contains("kid");
        assertThat(header.getIncludedParameters()).contains("x5u");
        assertThat(header.getIncludedParameters()).contains("x5c");
        assertThat(header.getIncludedParameters()).contains("apu");
        assertThat(header.getIncludedParameters()).contains("apv");
        assertThat(header.getIncludedParameters()).contains("p2s");
        assertThat(header.getIncludedParameters()).contains("p2c");
        assertThat(header.getIncludedParameters()).contains("iv");
        assertThat(header.getIncludedParameters()).contains("tag");
        assertThat(header.getIncludedParameters()).contains("xCustom");
        assertThat(header.getIncludedParameters()).hasSize(17);
    }

    @Test
    public void testCrit()
            throws Exception {

        Set<String> crit = new HashSet<>();
        crit.add("iat");
        crit.add("exp");
        crit.add("nbf");

        JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256).
                criticalParams(crit).
                build();

        assertThat(h.getCriticalParams().size()).isEqualTo(3);

        Base64URLValue b64url = h.toBase64URL();

        // Parse back
        h = JWEHeader.parse(b64url);

        crit = h.getCriticalParams();

        assertThat(crit).contains("iat");
        assertThat(crit).contains("exp");
        assertThat(crit).contains("nbf");

        assertThat(crit.size()).isEqualTo(3);
    }

    @Test
    public void testRejectNone() {

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                new JWEHeader(new JWEAlgorithm("none"), EncryptionMethod.A128CBC_HS256));

    }

    @Test
    public void testBuilder()
            throws Exception {

        JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
                type(JOSEObjectType.JOSE).
                contentType("application/json").
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                jwkURL(new URI("http://example.com/jwk.json")).
                jwk(new OctetSequenceKey.Builder(new Base64URLValue("xyz")).build()).
                x509CertURL(new URI("http://example.com/cert.pem")).
                x509CertSHA256Thumbprint(new Base64URLValue("abc256")).
                x509CertChain(Arrays.asList(new Base64Value("abc"), new Base64Value("def"))).
                keyID("123").
                compressionAlgorithm(CompressionAlgorithm.DEF).
                agreementPartyUInfo(new Base64URLValue("qwe")).
                agreementPartyVInfo(new Base64URLValue("rty")).
                pbes2Salt(new Base64URLValue("uiop")).
                pbes2Count(1000).
                iv(new Base64URLValue("101010")).
                authTag(new Base64URLValue("202020")).
                parameter("exp", 123).
                parameter("nbf", 456).
                build();

        assertThat(h.getAlgorithm()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(h.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
        assertThat(h.getType()).isEqualTo(JOSEObjectType.JOSE);
        assertThat(h.getContentType()).isEqualTo("application/json");
        assertThat(h.getCriticalParams()).contains("exp");
        assertThat(h.getCriticalParams()).contains("nbf");
        assertThat(h.getCriticalParams().size()).isEqualTo(2);
        assertThat(h.getJWKURL().toString()).isEqualTo("http://example.com/jwk.json");
        assertThat(((OctetSequenceKey) h.getJWK()).getKeyValue().toString()).isEqualTo("xyz");
        assertThat(h.getX509CertURL().toString()).isEqualTo("http://example.com/cert.pem");
        assertThat(h.getX509CertSHA256Thumbprint().toString()).isEqualTo("abc256");
        assertThat(h.getX509CertChain().get(0).toString()).isEqualTo("abc");
        assertThat(h.getX509CertChain().get(1).toString()).isEqualTo("def");
        assertThat(h.getX509CertChain().size()).isEqualTo(2);
        assertThat(h.getKeyID()).isEqualTo("123");
        assertThat(h.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
        assertThat(h.getAgreementPartyUInfo().toString()).isEqualTo("qwe");
        assertThat(h.getAgreementPartyVInfo().toString()).isEqualTo("rty");
        assertThat(h.getPBES2Salt().toString()).isEqualTo("uiop");
        assertThat(h.getPBES2Count()).isEqualTo(1000);
        assertThat(h.getIV().toString()).isEqualTo("101010");
        assertThat(h.getAuthTag().toString()).isEqualTo("202020");
        assertThat(((Integer) h.getCustomParameter("exp")).intValue()).isEqualTo(123);
        assertThat(((Integer) h.getCustomParameter("nbf")).intValue()).isEqualTo(456);
        assertThat(h.getCustomParameters().size()).isEqualTo(2);
        assertThat(h.getParsedBase64URL()).isNull();

        assertThat(h.getIncludedParameters()).contains("alg");
        assertThat(h.getIncludedParameters()).contains("enc");
        assertThat(h.getIncludedParameters()).contains("typ");
        assertThat(h.getIncludedParameters()).contains("cty");
        assertThat(h.getIncludedParameters()).contains("crit");
        assertThat(h.getIncludedParameters()).contains("jku");
        assertThat(h.getIncludedParameters()).contains("jwk");
        assertThat(h.getIncludedParameters()).contains("x5u");
        assertThat(h.getIncludedParameters()).contains("x5t#S256");
        assertThat(h.getIncludedParameters()).contains("x5c");
        assertThat(h.getIncludedParameters()).contains("kid");
        assertThat(h.getIncludedParameters()).contains("zip");
        assertThat(h.getIncludedParameters()).contains("apu");
        assertThat(h.getIncludedParameters()).contains("apv");
        assertThat(h.getIncludedParameters()).contains("p2s");
        assertThat(h.getIncludedParameters()).contains("p2c");
        assertThat(h.getIncludedParameters()).contains("iv");
        assertThat(h.getIncludedParameters()).contains("tag");
        assertThat(h.getIncludedParameters()).contains("exp");
        assertThat(h.getIncludedParameters()).contains("nbf");
        assertThat(h.getIncludedParameters()).hasSize(20);
    }

    @Test
    public void testBuilderWithCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put("x", "1");
        customParams.put("y", "2");

        JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
                parameters(customParams).
                build();

        assertThat(h.getCustomParameter("x")).isEqualTo("1");
        assertThat(h.getCustomParameter("y")).isEqualTo("2");
        assertThat(h.getCustomParameters().size()).isEqualTo(2);
    }

    @Test
    // iss #333
    public void testParseHeaderWithNullTyp()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("alg", JWEAlgorithm.DIR.getName());
        builder.add("enc", EncryptionMethod.A128GCM.getName());
        builder.addNull("typ");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(3);

        Header header = JWEHeader.parse(jsonObject.toString());
        assertThat(header.getType()).isNull();
    }

    @Test
    // iss #334
    public void testParseHeaderWithNullCrit()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", JWEAlgorithm.DIR.getName());
        builder.add("enc", EncryptionMethod.A128GCM.getName());
        builder.addNull("crit");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(3);

        Header header = JWEHeader.parse(jsonObject);
        assertThat(header.getCriticalParams()).isEmpty();
    }

    @Test
    public void testParseHeaderWithNullJWK()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("alg", JWEAlgorithm.DIR.getName());
        builder.add("enc", EncryptionMethod.A128GCM.getName());
        builder.addNull("jwk");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(3);

        JWEHeader header = JWEHeader.parse(jsonObject);
        assertThat(header.getJWK()).isNull();
    }

    @Test
    public void testParseHeaderWithNullZIP()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("alg", JWEAlgorithm.DIR.getName());
        builder.add("enc", EncryptionMethod.A128GCM.getName());
        builder.addNull("zip");
        JsonObject jsonObject = builder.build();
        assertThat(jsonObject).hasSize(3);

        JWEHeader header = JWEHeader.parse(jsonObject.toString());
        assertThat(header.getCompressionAlgorithm()).isNull();
    }

    @Test
    public void testFilterCustomClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("p2s", Base64URLValue.encode("something"));
        claims.put("p2c", 1234);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .parameters(claims)
                .build();

        // Test if values from Custom Claims are migrated to 'real' properties
        assertThat(header.getPBES2Salt().decode()).isEqualTo("something".getBytes());
        assertThat(header.getPBES2Count()).isEqualTo(1234);
        assertThat(header.getCustomParameters()).isEmpty();
    }


    @Test
    public void customParam_supportSpecialCases() {
        Base64URLValue salt = Base64URLValue.encode("test");
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .parameter("p2s", salt)
                .parameter("p2c", 123)
                .build();

        assertThat(header.getCustomParameters()).isEmpty();  // They are all converted to the correct property
        assertThat(header.getPBES2Count()).isEqualTo(123);
        assertThat(header.getPBES2Salt().decode()).isEqualTo("test".getBytes());
    }

    @Test
    public void customParam_specialCases_type1() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                        .parameter("p2s", new Object())
                        .build());

        assertThat(exception.getMessage()).isEqualTo("The type of the parameter \"p2s\" must be Base64URLValue.");
    }

    @Test
    public void customParam_specialCases_type2() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                        .parameter("p2c", new Object())
                        .build());

        assertThat(exception.getMessage()).isEqualTo("The type of the parameter \"p2c\" must be Integer.");
    }

    @Test
    public void getRegisteredParameterNames() {
        assertThat(JWEHeader.getRegisteredParameterNames()).hasSize(19);
    }
}
