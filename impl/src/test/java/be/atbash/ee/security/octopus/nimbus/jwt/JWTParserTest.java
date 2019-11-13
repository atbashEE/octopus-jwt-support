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
package be.atbash.ee.security.octopus.nimbus.jwt;


import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import org.junit.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWT parser. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-19
 */
public class JWTParserTest {

    @Test
    public void testParsePlainJWT()
            throws Exception {

        String s = "eyJhbGciOiJub25lIn0" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                ".";

        JWT jwt = JWTParser.parse(s);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);

        assertThat(jwt).isInstanceOf(PlainJWT.class);

        PlainJWT plainJWT = (PlainJWT) jwt;

        assertThat(plainJWT.getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(plainJWT.getHeader().getType()).isNull();
        assertThat(plainJWT.getHeader().getContentType()).isNull();

        JWTClaimsSet cs = plainJWT.getJWTClaimsSet();

        assertThat(cs.getIssuer()).isEqualTo("joe");
        assertThat(cs.getExpirationTime()).isEqualTo(new Date(1300819380L * 1000));
        assertThat((Boolean) cs.getClaim("http://example.com/is_root")).isTrue();
    }

    @Test
    public void testParseEncryptedJWT()
            throws Exception {

        String s = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" +
                "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" +
                "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" +
                "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" +
                "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" +
                "1rZgN5TiysnmzTROF869lQ." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" +
                "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." +
                "fiK51VwhsxJ-siBMR-YFiA";

        JWT jwt = JWTParser.parse(s);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.RSA1_5);

        assertThat(jwt).isInstanceOf(EncryptedJWT.class);

        EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        assertThat(encryptedJWT.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.RSA1_5);
        assertThat(encryptedJWT.getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A128CBC_HS256);
        assertThat(encryptedJWT.getHeader().getType()).isNull();
        assertThat(encryptedJWT.getHeader().getContentType()).isNull();
    }
}
