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
package be.atbash.ee.security.octopus.nimbus.jwt.jwe;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.Filters;
import be.atbash.ee.security.octopus.keys.TestKeys;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.*;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKIdentifiers;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyUse;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.*;


/**
 * Tests JWE header parsing and serialisation.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class JWEHeaderTest {


    @Test
    public void testMinimalConstructor() {

        JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.A128KW);
        Assertions.assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
        Assertions.assertThat(header.getJWKURL()).isNull();
        Assertions.assertThat(header.getJWK()).isNull();
        Assertions.assertThat(header.getX509CertURL()).isNull();
        Assertions.assertThat(header.getX509CertSHA256Thumbprint()).isNull();
        Assertions.assertThat(header.getX509CertChain()).isNull();
        Assertions.assertThat(header.getType()).isNull();
        Assertions.assertThat(header.getContentType()).isNull();
        Assertions.assertThat(header.getCriticalParams()).isNull();
        Assertions.assertThat(header.getEphemeralPublicKey()).isNull();
        Assertions.assertThat(header.getCompressionAlgorithm()).isNull();
        Assertions.assertThat(header.getAgreementPartyUInfo()).isNull();
        Assertions.assertThat(header.getAgreementPartyVInfo()).isNull();
        Assertions.assertThat(header.getPBES2Salt()).isNull();
        Assertions.assertThat(header.getIV()).isNull();
        Assertions.assertThat(header.getAuthTag()).isNull();
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(0);
        Assertions.assertThat(header.getCustomParameters()).isEmpty();
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

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        Assertions.assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        Assertions.assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        Assertions.assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        Assertions.assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(1000);

        Assertions.assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        Assertions.assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        Assertions.assertThat(header.getIncludedParameters()).contains("alg");
        Assertions.assertThat(header.getIncludedParameters()).contains("typ");
        Assertions.assertThat(header.getIncludedParameters()).contains("enc");
        Assertions.assertThat(header.getIncludedParameters()).contains("zip");
        Assertions.assertThat(header.getIncludedParameters()).contains("jku");
        Assertions.assertThat(header.getIncludedParameters()).contains("jwk");
        Assertions.assertThat(header.getIncludedParameters()).contains("kid");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5u");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5c");
        Assertions.assertThat(header.getIncludedParameters()).contains("apu");
        Assertions.assertThat(header.getIncludedParameters()).contains("apv");
        Assertions.assertThat(header.getIncludedParameters()).contains("p2s");
        Assertions.assertThat(header.getIncludedParameters()).contains("p2c");
        Assertions.assertThat(header.getIncludedParameters()).contains("iv");
        Assertions.assertThat(header.getIncludedParameters()).contains("tag");
        Assertions.assertThat(header.getIncludedParameters()).contains("xCustom");
        Assertions.assertThat(header.getIncludedParameters()).hasSize(17);

        // Test copy constructor
        header = new JWEHeader(header);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        Assertions.assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        Assertions.assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        Assertions.assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        Assertions.assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(1000);

        Assertions.assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        Assertions.assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);
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
        parameters.put(HeaderParameterNames.TYPE, new JOSEObjectType("JWT"));
        parameters.put(HeaderParameterNames.COMPRESSION_ALGORITHM, CompressionAlgorithm.DEF);
        parameters.put(HeaderParameterNames.JWK_SET_URL, new URI("https://example.com/jku.json"));
        parameters.put(HeaderParameterNames.JSON_WEB_KEY, jwk);
        parameters.put(HeaderParameterNames.X_509_URL, new URI("https://example/cert.b64"));
        parameters.put("x5t256", new Base64URLValue("789asd"));
        parameters.put(HeaderParameterNames.X_509_CERT_CHAIN, certChain);
        parameters.put(HeaderParameterNames.KEY_ID, "1234");
        parameters.put(HeaderParameterNames.AGREEMENT_PARTY_U_INFO, new Base64URLValue("abc"));
        parameters.put(HeaderParameterNames.AGREEMENT_PARTY_V_INFO, new Base64URLValue("xyz"));
        parameters.put(HeaderParameterNames.PBES2_SALT_INPUT, new Base64URLValue("omg"));
        parameters.put(HeaderParameterNames.PBES2_COUNT, 1000);
        parameters.put(HeaderParameterNames.INITIALIZATION_VECTOR, new Base64URLValue("101010"));
        parameters.put(HeaderParameterNames.AUTHENTICATION_TAG, new Base64URLValue("202020"));
        parameters.put("xCustom", "+++");

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).
                parameters(parameters).
                build();


        Base64URLValue base64URL = header.toBase64URL();

        // Parse back
        header = JWEHeader.parse(base64URL);

        Assertions.assertThat(header.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        Assertions.assertThat(header.getType()).isEqualTo(new JOSEObjectType("JWT"));
        Assertions.assertThat(header.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        Assertions.assertThat(header.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
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

        Assertions.assertThat(header.getAgreementPartyUInfo()).isEqualTo(new Base64URLValue("abc"));
        Assertions.assertThat(header.getAgreementPartyVInfo()).isEqualTo(new Base64URLValue("xyz"));

        Assertions.assertThat(header.getPBES2Salt()).isEqualTo(new Base64URLValue("omg"));
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(1000);

        Assertions.assertThat(header.getIV()).isEqualTo(new Base64URLValue("101010"));
        Assertions.assertThat(header.getAuthTag()).isEqualTo(new Base64URLValue("202020"));

        Assertions.assertThat(header.getCustomParameter("xCustom")).isEqualTo("+++");
        Assertions.assertThat(header.getCustomParameters().size()).isEqualTo(1);

        Assertions.assertThat(header.getParsedBase64URL()).isEqualTo(base64URL);

        Assertions.assertThat(header.getIncludedParameters()).contains("alg");
        Assertions.assertThat(header.getIncludedParameters()).contains("typ");
        Assertions.assertThat(header.getIncludedParameters()).contains("enc");
        Assertions.assertThat(header.getIncludedParameters()).contains("zip");
        Assertions.assertThat(header.getIncludedParameters()).contains("jku");
        Assertions.assertThat(header.getIncludedParameters()).contains("jwk");
        Assertions.assertThat(header.getIncludedParameters()).contains("kid");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5u");
        Assertions.assertThat(header.getIncludedParameters()).contains("x5c");
        Assertions.assertThat(header.getIncludedParameters()).contains("apu");
        Assertions.assertThat(header.getIncludedParameters()).contains("apv");
        Assertions.assertThat(header.getIncludedParameters()).contains("p2s");
        Assertions.assertThat(header.getIncludedParameters()).contains("p2c");
        Assertions.assertThat(header.getIncludedParameters()).contains("iv");
        Assertions.assertThat(header.getIncludedParameters()).contains("tag");
        Assertions.assertThat(header.getIncludedParameters()).contains("xCustom");
        Assertions.assertThat(header.getIncludedParameters()).hasSize(17);
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

        Assertions.assertThat(h.getCriticalParams().size()).isEqualTo(3);

        Base64URLValue b64url = h.toBase64URL();

        // Parse back
        h = JWEHeader.parse(b64url);

        crit = h.getCriticalParams();

        Assertions.assertThat(crit).contains("iat");
        Assertions.assertThat(crit).contains("exp");
        Assertions.assertThat(crit).contains("nbf");

        Assertions.assertThat(crit.size()).isEqualTo(3);
    }

    @Test
    public void testRejectNone() {

        Assertions.assertThatThrownBy(
                        () -> new JWEHeader(new JWEAlgorithm("none"), EncryptionMethod.A128CBC_HS256))
                .isInstanceOf(IllegalArgumentException.class);

    }

    @Test
    public void testBuilder()
            throws Exception {

        List<AtbashKey> keys = TestKeys.generateRSAKeys("kid");

        AtbashKey publicKey = Filters.findPublicKey(keys);
        RSAKey jwk = new RSAKey.Builder(publicKey).build();

        JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
                type(JOSEObjectType.JOSE).
                contentType("application/json").
                criticalParams(new HashSet<>(Arrays.asList("exp", "nbf"))).
                jwkURL(new URI("http://example.com/jwk.json")).
                jwk(jwk).
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

        Assertions.assertThat(h.getAlgorithm()).isEqualTo(JWEAlgorithm.A128KW);
        Assertions.assertThat(h.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
        Assertions.assertThat(h.getType()).isEqualTo(JOSEObjectType.JOSE);
        Assertions.assertThat(h.getContentType()).isEqualTo("application/json");
        Assertions.assertThat(h.getCriticalParams()).contains("exp");
        Assertions.assertThat(h.getCriticalParams()).contains("nbf");
        Assertions.assertThat(h.getCriticalParams().size()).isEqualTo(2);
        Assertions.assertThat(h.getJWKURL().toString()).isEqualTo("http://example.com/jwk.json");
        Assertions.assertThat(((RSAKey) h.getJWK()).toRSAPublicKey()).isEqualTo(publicKey.getKey());
        Assertions.assertThat(h.getX509CertURL().toString()).isEqualTo("http://example.com/cert.pem");
        Assertions.assertThat(h.getX509CertSHA256Thumbprint().toString()).isEqualTo("abc256");
        Assertions.assertThat(h.getX509CertChain().get(0).toString()).isEqualTo("abc");
        Assertions.assertThat(h.getX509CertChain().get(1).toString()).isEqualTo("def");
        Assertions.assertThat(h.getX509CertChain().size()).isEqualTo(2);
        Assertions.assertThat(h.getKeyID()).isEqualTo("123");
        Assertions.assertThat(h.getCompressionAlgorithm()).isEqualTo(CompressionAlgorithm.DEF);
        Assertions.assertThat(h.getAgreementPartyUInfo().toString()).isEqualTo("qwe");
        Assertions.assertThat(h.getAgreementPartyVInfo().toString()).isEqualTo("rty");
        Assertions.assertThat(h.getPBES2Salt().toString()).isEqualTo("uiop");
        Assertions.assertThat(h.getPBES2Count()).isEqualTo(1000);
        Assertions.assertThat(h.getIV().toString()).isEqualTo("101010");
        Assertions.assertThat(h.getAuthTag().toString()).isEqualTo("202020");
        Assertions.assertThat(((Integer) h.getCustomParameter("exp")).intValue()).isEqualTo(123);
        Assertions.assertThat(((Integer) h.getCustomParameter("nbf")).intValue()).isEqualTo(456);
        Assertions.assertThat(h.getCustomParameters().size()).isEqualTo(2);
        Assertions.assertThat(h.getParsedBase64URL()).isNull();

        Assertions.assertThat(h.getIncludedParameters()).contains("alg");
        Assertions.assertThat(h.getIncludedParameters()).contains("enc");
        Assertions.assertThat(h.getIncludedParameters()).contains("typ");
        Assertions.assertThat(h.getIncludedParameters()).contains("cty");
        Assertions.assertThat(h.getIncludedParameters()).contains("crit");
        Assertions.assertThat(h.getIncludedParameters()).contains("jku");
        Assertions.assertThat(h.getIncludedParameters()).contains("jwk");
        Assertions.assertThat(h.getIncludedParameters()).contains("x5u");
        Assertions.assertThat(h.getIncludedParameters()).contains("x5t#S256");
        Assertions.assertThat(h.getIncludedParameters()).contains("x5c");
        Assertions.assertThat(h.getIncludedParameters()).contains("kid");
        Assertions.assertThat(h.getIncludedParameters()).contains("zip");
        Assertions.assertThat(h.getIncludedParameters()).contains("apu");
        Assertions.assertThat(h.getIncludedParameters()).contains("apv");
        Assertions.assertThat(h.getIncludedParameters()).contains("p2s");
        Assertions.assertThat(h.getIncludedParameters()).contains("p2c");
        Assertions.assertThat(h.getIncludedParameters()).contains("iv");
        Assertions.assertThat(h.getIncludedParameters()).contains("tag");
        Assertions.assertThat(h.getIncludedParameters()).contains("exp");
        Assertions.assertThat(h.getIncludedParameters()).contains("nbf");
        Assertions.assertThat(h.getIncludedParameters()).hasSize(20);
    }

    @Test
    public void testBuilderWithCustomParams() {

        Map<String, Object> customParams = new HashMap<>();
        customParams.put(JWKIdentifiers.X_COORD, "1");
        customParams.put(JWKIdentifiers.Y_COORD, "2");

        JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
                parameters(customParams).
                build();

        Assertions.assertThat(h.getCustomParameter("x")).isEqualTo("1");
        Assertions.assertThat(h.getCustomParameter("y")).isEqualTo("2");
        Assertions.assertThat(h.getCustomParameters().size()).isEqualTo(2);
    }

    @Test
    // iss #333
    public void testParseHeaderWithNullTyp()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
        builder.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
        builder.addNull(HeaderParameterNames.TYPE);
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(3);

        Header header = JWEHeader.parse(jsonObject.toString());
        Assertions.assertThat(header.getType()).isNull();
    }

    @Test
    // iss #334
    public void testParseHeaderWithNullCrit()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
        builder.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
        builder.addNull("crit");
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(3);

        Header header = JWEHeader.parse(jsonObject);
        Assertions.assertThat(header.getCriticalParams()).isEmpty();
    }

    @Test
    public void testParseHeaderWithNullJWK()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
        builder.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
        builder.addNull(HeaderParameterNames.JSON_WEB_KEY);
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(3);

        JWEHeader header = JWEHeader.parse(jsonObject);
        Assertions.assertThat(header.getJWK()).isNull();
    }

    @Test
    public void testParseHeaderWithNullZIP()
            throws ParseException {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
        builder.add(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
        builder.addNull(HeaderParameterNames.COMPRESSION_ALGORITHM);
        JsonObject jsonObject = builder.build();
        Assertions.assertThat(jsonObject).hasSize(3);

        JWEHeader header = JWEHeader.parse(jsonObject.toString());
        Assertions.assertThat(header.getCompressionAlgorithm()).isNull();
    }

    @Test
    public void testFilterCustomClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put(HeaderParameterNames.PBES2_SALT_INPUT, Base64URLValue.encode("something"));
        claims.put(HeaderParameterNames.PBES2_COUNT, 1234);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .parameters(claims)
                .build();

        // Test if values from Custom Claims are migrated to 'real' properties
        Assertions.assertThat(header.getPBES2Salt().decode()).isEqualTo("something".getBytes());
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(1234);
        Assertions.assertThat(header.getCustomParameters()).isEmpty();
    }


    @Test
    public void customParam_supportSpecialCases() {
        Base64URLValue salt = Base64URLValue.encode("test");
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .parameter(HeaderParameterNames.PBES2_SALT_INPUT, salt)
                .parameter(HeaderParameterNames.PBES2_COUNT, 123)
                .build();

        Assertions.assertThat(header.getCustomParameters()).isEmpty();  // They are all converted to the correct property
        Assertions.assertThat(header.getPBES2Count()).isEqualTo(123);
        Assertions.assertThat(header.getPBES2Salt().decode()).isEqualTo("test".getBytes());
    }

    @Test
    public void customParam_specialCases_type1() {

        Assertions.assertThatThrownBy(() ->
                        new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                                .parameter(HeaderParameterNames.PBES2_SALT_INPUT, new Object())
                                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The type of the parameter \"" + HeaderParameterNames.PBES2_SALT_INPUT + "\" must be Base64URLValue.");
    }

    @Test
    public void customParam_specialCases_type2() {

        Assertions.assertThatThrownBy(() ->
                        new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                                .parameter(HeaderParameterNames.PBES2_COUNT, new Object())
                                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The type of the parameter \"" + HeaderParameterNames.PBES2_COUNT + "\" must be Integer.");
    }

    @Test
    public void getRegisteredParameterNames() {
        Assertions.assertThat(JWEHeader.getRegisteredParameterNames()).hasSize(19);
    }

    @Test
    public void testParseHeaderWithNonPublicJWK() throws JOSEException {

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

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
                        () -> JWEHeader.parse(jsonObjectBuilder.build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Non-public key in jwk header parameter");
    }

}
