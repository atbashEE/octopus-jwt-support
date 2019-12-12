/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.nimbus;


import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


public class SampleCertificates {

    // Real world sample cert chain for oracle.com web site
    public static final List<Base64Value> SAMPLE_X5C_RSA = Arrays.asList(
            new Base64Value(
                    "MIIJcTCCCFmgAwIBAgIQCa4884BqoV7BKWdHq2qgOTANBgkqhkiG9w0BAQsFADBe" +
                            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" +
                            "d3cuZGlnaWNlcnQuY29tMR0wGwYDVQQDExRHZW9UcnVzdCBSU0EgQ0EgMjAxODAe" +
                            "Fw0xNzEyMjMwMDAwMDBaFw0xODA0MDcxMjAwMDBaMIGaMQswCQYDVQQGEwJVUzET" +
                            "MBEGA1UECBMKQ2FsaWZvcm5pYTEXMBUGA1UEBxMOUmVkd29vZCBTaG9yZXMxGzAZ" +
                            "BgNVBAoTEk9yYWNsZSBDb3Jwb3JhdGlvbjEnMCUGA1UECxMeQ29udGVudCBNYW5h" +
                            "Z2VtZW50IFNlcnZpY2VzIElUMRcwFQYDVQQDEw53d3cub3JhY2xlLmNvbTCCASIw" +
                            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANYei70IDL2XQjCxnFXfQp7XxzKe" +
                            "uAl+p3hoYLEIUhKMPbRc0uWl0VA+X+U7P0pYvMP2AG0Hgd3UU4URfl63IeS1tOrD" +
                            "VGEQ4pQRNuDp2vzsFMOr/+fHC37mv7aU9zdO0hY0VZdDqabEZXkYgOdUIvM1PAKq" +
                            "aEf87lRUwN47Skp0T1rgO/WuC8TWUL1dYxluYH3GRz10eEKLBsD5yXWaEDmnqpCu" +
                            "IiuwfMVdS0dffUXhtm+gzM608PW+01bIBlcdM8Lxzfanui29h4m6gqGOGf03FoDm" +
                            "kWPnwVh+kDdcr45wLAnEWzP9bvwACaDTgHof07pCS0zKKwo+7xIiQ3cpYoECAwEA" +
                            "AaOCBewwggXoMB8GA1UdIwQYMBaAFJBY/7CcdahRVHex7fKjQxY4nmzFMB0GA1Ud" +
                            "DgQWBBR6oFhsnYiof5l3BA6g4k/E/dvd6TCCBGUGA1UdEQSCBFwwggRYgg53d3cu" +
                            "b3JhY2xlLmNvbYIVZnVzaW9uaGVscC5vcmFjbGUuY29tgg9kb2NzLm9yYWNsZS5j" +
                            "b22CEHNpdGVzLm9yYWNsZS5jb22CFG15YnVpbGRlci5vcmFjbGUuY29tghFzZWFy" +
                            "Y2gub3JhY2xlLmNvbYIKb3JhY2xlLmNvbYILd3d3LmdvLmphdmGCDGNsb3VkLm9y" +
                            "YWNsZYIRZm9ydW1zLm9yYWNsZS5jb22CGGZpbi1mdXNpb25jcm0ub3JhY2xlLmNv" +
                            "bYIbY2xvdWRtYXJrZXRwbGFjZS5vcmFjbGUuY29tghRlZGVsaXZlcnkub3JhY2xl" +
                            "LmNvbYIMbS5vcmFjbGUuY29tghRteXByb2ZpbGUub3JhY2xlLmNvbYIYcHJqLWZ1" +
                            "c2lvbmNybS5vcmFjbGUuY29tgg9zY3N4Lm9yYWNsZS5jb22CFHByZXNzcm9vbS5v" +
                            "cmFjbGUuY29tghtiaWFwcHMtZnVzaW9uY3JtLm9yYWNsZS5jb22CF2JpLWZ1c2lv" +
                            "bmNybS5vcmFjbGUuY29tghxyZXNlbGxlcmVkdWNhdGlvbi5vcmFjbGUuY29tghRj" +
                            "bi5mb3J1bXMub3JhY2xlLmNvbYIRcG9ydGFsLm9yYWNsZS5jb22CGGhjbS1mdXNp" +
                            "b25jcm0ub3JhY2xlLmNvbYIUZnVzaW9uY3JtLm9yYWNsZS5jb22CEGJsb2dzLm9y" +
                            "YWNsZS5jb22CD21hcHMub3JhY2xlLmNvbYILamF2YS5vcmFjbGWCF2RpZ2l0YWxt" +
                            "ZWRpYS5vcmFjbGUuY29tghFzdGF0aWMub3JhY2xlLmNvbYIUb3JhY2xlZm91bmRh" +
                            "dGlvbi5vcmeCGHByYy1mdXNpb25jcm0ub3JhY2xlLmNvbYIUa3IuZm9ydW1zLm9y" +
                            "YWNsZS5jb22CEm15c2l0ZXMub3JhY2xlLmNvbYIUbXlwcm9jZXNzLm9yYWNsZS5j" +
                            "b22CEnByb2ZpbGUub3JhY2xlLmNvbYIMd3d3LmphdmEuY29tghh3d3cub3JhY2xl" +
                            "Zm91bmRhdGlvbi5vcmeCFGVsb2NhdGlvbi5vcmFjbGUuY29tghpteXZpc3VhbGl6" +
                            "YXRpb24ub3JhY2xlLmNvbYIQaXR3ZWIub3JhY2xlLmNvbYIIamF2YS5jb22CFGNv" +
                            "bW11bml0eS5vcmFjbGUuY29tghhjcm0tZnVzaW9uY3JtLm9yYWNsZS5jb22CGHNj" +
                            "bS1mdXNpb25jcm0ub3JhY2xlLmNvbYIQY2xvdWQub3JhY2xlLmNvbYIHZ28uamF2" +
                            "YYIUZWR1Y2F0aW9uLm9yYWNsZS5jb22CEnN1cHBvcnQub3JhY2xlLmNvbYIRZXZl" +
                            "bnRzLm9yYWNsZS5jb22CEHdpa2lzLm9yYWNsZS5jb22CF2ljLWZ1c2lvbmNybS5v" +
                            "cmFjbGUuY29tghF3d3cub3JhY2xlaW1nLmNvbYIUZGV2ZWxvcGVyLm9yYWNsZS5j" +
                            "b20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD" +
                            "AjA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vY2RwLmdlb3RydXN0LmNvbS9HZW9U" +
                            "cnVzdFJTQUNBMjAxOC5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggr" +
                            "BgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIw" +
                            "dQYIKwYBBQUHAQEEaTBnMCYGCCsGAQUFBzABhhpodHRwOi8vc3RhdHVzLmdlb3Ry" +
                            "dXN0LmNvbTA9BggrBgEFBQcwAoYxaHR0cDovL2NhY2VydHMuZ2VvdHJ1c3QuY29t" +
                            "L0dlb1RydXN0UlNBQ0EyMDE4LmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUA" +
                            "A4IBAQAx68yGs23PvbYCg/K8rmICEKr+oj7yyOUXZtoqlxOG8g5q8FztahuHVzJl" +
                            "D2pmL9Egqw/EmFX+2FkldsLZR1GFw49amvNwuQgYav1ubjpItKDp4HUlo4PARd4s" +
                            "1b005UCIvVQJj+9oqWWo5qA3eDVWPzOmK3iC5KxTpcyeEjPAL0DwHlx1vXEIB555" +
                            "XYaB4oeb5y77Y/uzSc6aR0FK9Hp/Ary4v0RsWCZ9PGu81nG14y4YyHizmxk/F5lN" +
                            "36GnCJNFJYIQO+kcpXvxipj0dzHkOSgNltVrJiupFsdxxOJJxaxuqkFU+86XRvtG" +
                            "bKskJ/jINEW4ig3Aa/6iJxbhvYFE"),

            new Base64Value(
                    "MIIEizCCA3OgAwIBAgIQBUb+GCP34ZQdo5/OFMRhczANBgkqhkiG9w0BAQsFADBh" +
                            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" +
                            "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD" +
                            "QTAeFw0xNzExMDYxMjIzNDVaFw0yNzExMDYxMjIzNDVaMF4xCzAJBgNVBAYTAlVT" +
                            "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j" +
                            "b20xHTAbBgNVBAMTFEdlb1RydXN0IFJTQSBDQSAyMDE4MIIBIjANBgkqhkiG9w0B" +
                            "AQEFAAOCAQ8AMIIBCgKCAQEAv4rRY03hGOqHXegWPI9/tr6HFzekDPgxP59FVEAh" +
                            "150Hm8oDI0q9m+2FAmM/n4W57Cjv8oYi2/hNVEHFtEJ/zzMXAQ6CkFLTxzSkwaEB" +
                            "2jKgQK0fWeQz/KDDlqxobNPomXOMJhB3y7c/OTLo0lko7geG4gk7hfiqafapa59Y" +
                            "rXLIW4dmrgjgdPstU0Nigz2PhUwRl9we/FAwuIMIMl5cXMThdSBK66XWdS3cLX18" +
                            "4ND+fHWhTkAChJrZDVouoKzzNYoq6tZaWmyOLKv23v14RyZ5eqoi6qnmcRID0/i6" +
                            "U9J5nL1krPYbY7tNjzgC+PBXXcWqJVoMXcUw/iBTGWzpwwIDAQABo4IBQDCCATww" +
                            "HQYDVR0OBBYEFJBY/7CcdahRVHex7fKjQxY4nmzFMB8GA1UdIwQYMBaAFAPeUDVW" +
                            "0Uy7ZvCj4hsbw5eyPdFVMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEF" +
                            "BQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADA0BggrBgEFBQcBAQQo" +
                            "MCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBCBgNVHR8E" +
                            "OzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9i" +
                            "YWxSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxo" +
                            "dHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA0GCSqGSIb3DQEBCwUAA4IBAQAw" +
                            "8YdVPYQI/C5earp80s3VLOO+AtpdiXft9OlWwJLwKlUtRfccKj8QW/Pp4b7h6QAl" +
                            "ufejwQMb455OjpIbCZVS+awY/R8pAYsXCnM09GcSVe4ivMswyoCZP/vPEn/LPRhH" +
                            "hdgUPk8MlD979RGoUWz7qGAwqJChi28uRds3thx+vRZZIbEyZ62No0tJPzsSGSz8" +
                            "nQ//jP8BIwrzBAUH5WcBAbmvgWfrKcuv+PyGPqRcc4T55TlzrBnzAzZ3oClo9fTv" +
                            "O9PuiHMKrC6V6mgi0s2sa/gbXlPCD9Z24XUMxJElwIVTDuKB0Q4YMMlnpN/QChJ4" +
                            "B0AFsQ+DU0NCO+f78Xf7"),

            new Base64Value(
                    "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh" +
                            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" +
                            "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD" +
                            "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT" +
                            "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j" +
                            "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG" +
                            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB" +
                            "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97" +
                            "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt" +
                            "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P" +
                            "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4" +
                            "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO" +
                            "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR" +
                            "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw" +
                            "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr" +
                            "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg" +
                            "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF" +
                            "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls" +
                            "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk" +
                            "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=")
    );


    // Sample cert chain of size one, EC key
    public static final List<Base64Value> SAMPLE_X5C_EC;

    static {

        try {
            // Generate EC key pair
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(Curve.P_256.toECParameterSpec());
            KeyPair kp = gen.generateKeyPair();
            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

            // Generate EC certificate
            X500Name issuer = new X500Name("cn=c2id");
            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            Date now = new Date();
            Date nbf = new Date(now.getTime() - 1000L);
            Date exp = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000L); // in 1 year
            X500Name subject = new X500Name("cn=c2id");
            JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    nbf,
                    exp,
                    subject,
                    publicKey
            );
            KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
            x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
            X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
            X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
            assertThat(cert).isNotNull();
            SAMPLE_X5C_EC = Collections.unmodifiableList(Collections.singletonList(Base64Value.encode(cert.getEncoded())));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
