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
package be.atbash.ee.security.octopus.nimbus.util;


import be.atbash.ee.security.octopus.nimbus.SampleCertificates;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


public class X509CertChainUtilsTest {


    @Test
    public void testToBase64List_nullSafe()
            throws ParseException {

        assertThat(X509CertChainUtils.toBase64List(null)).isNull();
    }

    @Test
    public void testParseSample()
            throws ParseException {

        List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);

        assertThat(chain.get(0).getSigAlgName()).isEqualTo("SHA256withRSA");
        assertThat(chain.get(1).getSigAlgName()).isEqualTo("SHA256withRSA");
        assertThat(chain.get(2).getSigAlgName()).isEqualTo("SHA1withRSA");

        assertThat(chain.get(0).getSubjectDN().getName()).isEqualTo("CN=www.oracle.com, OU=Content Management Services IT, O=Oracle Corporation, L=Redwood Shores, ST=California, C=US");
        assertThat(chain.get(1).getSubjectDN().getName()).isEqualTo("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US");
        assertThat(chain.get(2).getSubjectDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");

        assertThat(chain.get(0).getIssuerDN().getName()).isEqualTo("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US");
        assertThat(chain.get(1).getIssuerDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");
        assertThat(chain.get(2).getIssuerDN().getName()).isEqualTo("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US");

        assertThat(chain.get(0).getType()).isEqualTo("X.509");
        assertThat(chain.get(1).getType()).isEqualTo("X.509");
        assertThat(chain.get(2).getType()).isEqualTo("X.509");

        assertThat(chain.get(0).getPublicKey().getAlgorithm()).isEqualTo("RSA");
        assertThat(chain.get(1).getPublicKey().getAlgorithm()).isEqualTo("RSA");
        assertThat(chain.get(2).getPublicKey().getAlgorithm()).isEqualTo("RSA");

        assertThat(ByteUtils.bitLength(chain.get(0).getPublicKey().getEncoded())).isEqualTo(2352);
        assertThat(ByteUtils.bitLength(chain.get(1).getPublicKey().getEncoded())).isEqualTo(2352);
        assertThat(ByteUtils.bitLength(chain.get(2).getPublicKey().getEncoded())).isEqualTo(2352);
    }
}
