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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.nimbus.SampleCertificates;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;


public class X509CertChainUtilsTest {


    @Test
    public void testToBase64List_nullSafe()
            throws ParseException {

        Assertions.assertThat(X509CertChainUtils.toBase64List(null)).isNull();
    }

    @Test
    public void testParseSample()
            throws ParseException {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);

        Assertions.assertThat(chain.get(0).getSigAlgName()).isEqualTo("SHA256withRSA");
        Assertions.assertThat(chain.get(1).getSigAlgName()).isEqualTo("SHA256withRSA");
        Assertions.assertThat(chain.get(2).getSigAlgName()).isEqualTo("SHA1withRSA");

        Assertions.assertThat(chain.get(0).getSubjectDN().getName()).isEqualTo("CN=www.oracle.com, OU=Content Management Services IT, O=Oracle Corporation, L=Redwood Shores, ST=California, C=US");
        Assertions.assertThat(chain.get(1).getSubjectDN().getName()).isEqualTo("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US");
        Assertions.assertThat(chain.get(2).getSubjectDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");

        Assertions.assertThat(chain.get(0).getIssuerDN().getName()).isEqualTo("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US");
        Assertions.assertThat(chain.get(1).getIssuerDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");
        Assertions.assertThat(chain.get(2).getIssuerDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");

        Assertions.assertThat(chain.get(0).getType()).isEqualTo("X.509");
        Assertions.assertThat(chain.get(1).getType()).isEqualTo("X.509");
        Assertions.assertThat(chain.get(2).getType()).isEqualTo("X.509");

        Assertions.assertThat(chain.get(0).getPublicKey().getAlgorithm()).isEqualTo("RSA");
        Assertions.assertThat(chain.get(1).getPublicKey().getAlgorithm()).isEqualTo("RSA");
        Assertions.assertThat(chain.get(2).getPublicKey().getAlgorithm()).isEqualTo("RSA");

        Assertions.assertThat(ByteUtils.bitLength(chain.get(0).getPublicKey().getEncoded())).isEqualTo(2352);
        Assertions.assertThat(ByteUtils.bitLength(chain.get(1).getPublicKey().getEncoded())).isEqualTo(2352);
        Assertions.assertThat(ByteUtils.bitLength(chain.get(2).getPublicKey().getEncoded())).isEqualTo(2352);
    }

    @Test
    public void testParseChainFromFile() throws IOException, CertificateException {

        File file = new File("src/test/resources/sample-cert-chains/c2id-net-chain.pem");
        List<X509Certificate> certChain = X509CertChainUtils.parse(file);

        Assertions.assertThat(certChain).hasSize(3);

        Assertions.assertThat(certChain.get(0).getSubjectDN().getName()).isEqualTo("CN=c2id.net");
        Assertions.assertThat(certChain.get(1).getSubjectDN().getName()).isEqualTo("CN=Amazon, OU=Server CA 1B, O=Amazon, C=US");
        Assertions.assertThat(certChain.get(2).getSubjectDN().getName()).isEqualTo("CN=Amazon Root CA 1, O=Amazon, C=US");

    }

    @Test
    public void testStore() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {

        File file = new File("src/test/resources/sample-cert-chains/c2id-net-chain.pem");
        List<X509Certificate> certChain = X509CertChainUtils.parse(file);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, "secretpassword".toCharArray());

        List<UUID> aliases = X509CertChainUtils.store(keyStore, certChain);

        List<String> subjects = new LinkedList<>();

        for (Enumeration<String> entryAliases = keyStore.aliases(); entryAliases.hasMoreElements(); ) {
            String alias = entryAliases.nextElement();
            Assertions.assertThat(aliases).contains(UUID.fromString(alias));
            subjects.add(((X509Certificate) keyStore.getCertificate(alias)).getSubjectDN().getName());
        }

        Assertions.assertThat(subjects).containsOnly("CN=c2id.net", "CN=Amazon, OU=Server CA 1B, O=Amazon, C=US", "CN=Amazon Root CA 1, O=Amazon, C=US");
    }
}
