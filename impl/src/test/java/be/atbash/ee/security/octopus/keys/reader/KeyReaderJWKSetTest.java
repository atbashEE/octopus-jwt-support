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
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.exception.ResourceNotFoundException;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.TestPasswordLookup;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyReaderJWKSetTest {

    private KeyReaderJWKSet reader = new KeyReaderJWKSet();

    private String data = "{ \"keys\" : [\n" +
            "{\"d\":\"lovapbjBkQ3sI6JLsqK8Dd0AK-wDon0Uz0NoOUlsacJJYLhX8Lx9KTFiA8IwtmigA67bevgeTRgsFXcCd8XyvkRASivNe1W5Fv28VK1g3O6RZ-WrLpqP49O4xhy-WENcUSQGU3wX5eFJDjSOGzlwFYaFN1Tj9C2JRj6Qsz6rGO63w8NUR9FTWd39DOj69ejuzzleNTmnYOTxGfOFq4S1KXHs4wlbgIoiIXDfACsu02PVOa7s1FojfUpaBlfc8y39MrLpMMyOVNwxwTyEEDBXcNYJ75O3g0VuuFs5v13Mg9H4p4Ca-7jjev9xuko0ySpaOWBkpDuC-41GF3v8p6YIQQ\",\"e\":\"AQAB\",\"qi\":\"o24qGe86eE9uoKF-RthiC6CCILcpFK51u9FpkGi__h3WdEPfwjJs6gwpvGGWU8ixfcQYimz27DjHpT1R8igryonh97kF0KgQ9yXiJlz8bDHs-OESqTXrJfZktO_-jSKYkhlzcL-jGU_SMeAluIL-M8esyA-vsbODc470ClSd02s\",\"q\":\"3oADsGnzvUMUcyg1PTnnIVjwFZ_FiDqw6yOxjJi1cSB31P475QxJbOD9P0M5k6DqcLiDvekatdCkl10nasHSjSGQtygU0KA-hGCkVuImTTciOs1cOEvG0nG0Dvtiy1IQ-6mwOiG_cuRah-pcJl8hiTxpsUxm43aTmq7SzeoilBk\",\"p\":\"5tFV-dg41gc-PCeesXnhRsk2IC_czI2O1sQ8wzRRLkzE7a6OidaWym-fkujFK0vysq5jRPwB7aLjCD1-6TktT0cvKOdu7nTrgX-cAe6v85IUXMpeyDG54kKj1THx5VFjAAy9fdCTBDhGhgCMMME_Ql5oWUg7F8SxUH8m8cmf3jk\",\"n\":\"yJz0jSniDu-6tzToc3ci7Nr2-UKZWYIaFIUwiELy0jvYefqJtKP0bqgC5mrN1GBfV1f4Q5qWWD34Ngahk05OMc8iyfmd1a1VDXBnc5d8gZuqRZGXctJQ5Ez_1nhLxeW3aPdEm6ZiC9J1dZRjVgkQYCTzaF8LW7V33EUuz1fXME46su239E0lQzLhVs2WJ61tKu50JFgEz7m4z9Qd60fjzxzCnhT7Aug5qltEqWwLvgZspzGAU96IntI0wmGCw_1r8qcw-ZK4_qN1r_ABWad2Br3wLdaIc54gP9FrSwuY2omlEtAcZkDIuCbMBIG4D5DaMuvkCJ9VQGx7ZTQtuqenkQ\",\"kty\":\"RSA\",\"dq\":\"W6px2qRL_pU8P5U5GdhZGKwDfWUthEppyPYTl9DyL4Eo3V9AXcUKGwk2THHtrpyE-ZuK6xq2HmGu7Y07SAhCLlK9xDeHG8xo9TC7g-_3x6gHOiKQ88CEUP73J5T5xrowtP3b1JdCwJrDkWtEO6rFrjxtbtYDLYMUnI2Z26uyQ0E\",\"dp\":\"HuFi30pOUFQnv2SNlrD3ssC4vRWqNLO7qIAYoQUe11LuBd6Us1xCUFMexkjeGCzRC5bJMTGGEIT6Wt_fWtSLe0_Kv243KS_7UhgAh0GnyK6CiueIRsBgXiUMRjmoY0XAOQF7WJnPEYF17fekyeEQ1ZBL5aYEQenOzzYzv6V5_gE\",\"kid\":\"rsa.pk.free\"}\n" +
            ",{\"d\":\"iRBc2Dct9I-wiASzpNXItm0gBu43dw_rjqdZ8BN5Ukk\",\"crv\":\"P-256\",\"kty\":\"EC\",\"y\":\"sGXT9uFyM_2yn3Z2upj5yV-9EUQEqqB664w7tMGjsnw\",\"x\":\"KISGNk7Q4NvmRlBtzzTQJLTIO1jj78cNvcRvcqrmRaY\",\"kid\":\"secp256r1-key\"}\n" +
            "]}\n";

    private String data2 = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"dc74e5f1-92a3-4f77-b824-d41db51d6ceb\",\"n\":\"7D3dav0yQCF4iKULd1NAIHWJIVhwLAa_b3YPPKmEyYIR8diYvfa1N4joO8tZosRUK_kpJETeeiUuLKVmdV-Ei6Fv3lfAmszO41rp3_3dOQQ4c_ZKp5_VJpfS1Rynd9kTfBxGDeu14sJiQJ9RmN6nTNk2iv9il3MPGG3XFNjxtLtxGzkPn1UZ1zt3mjmH-PkFis4aAFDbYJbbl9moYr_jd5QOmmDnkSqWsXyREneqhPPHMx1UWbISTfDQwjyIW_gdE1FbNNwsXqwoguaH29z9HbnDgWzqK6UiZATHl8etuoRNuZUBymxOQan-mZOxlzo9Z5dGOCFCUoOeGGibY2d_vw\"}]}";

    private String data3 = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"demo\",\"k\":\"eNbDd3kF8qW7rFjsdWZyBBN81_tnzOQS34FbAu6RmSfQ3tEOqCrMu0rhNhMKEt8C0UtrZ4lI5bQ2jikaZNdJVA\"}]}";

    @Test
    public void parseContent() {

        List<AtbashKey> keys = reader.parseContent(null, new TestPasswordLookup(), data);

        assertThat(keys).hasSize(4);

        Set<String> data = new HashSet<>();
        for (int i = 0; i < 4; i++) {

            AtbashKey atbashKey = keys.get(i);

            data.add(atbashKey.getKeyId() + " - " + atbashKey.getSecretKeyType().getKeyType().getValue() + " - " + atbashKey.getSecretKeyType().getAsymmetricPart());
        }

        assertThat(data).containsOnly("rsa.pk.free - RSA - PRIVATE", "secp256r1-key - EC - PUBLIC", "rsa.pk.free - RSA - PUBLIC", "secp256r1-key - EC - PRIVATE");

    }

    @Test
    public void parseContent2() {

        List<AtbashKey> keys = reader.parseContent(null, null, data2);
        assertThat(keys).hasSize(1);

        AtbashKey atbashKey = keys.get(0);
        String data = atbashKey.getKeyId() + " - " + atbashKey.getSecretKeyType().getKeyType().getValue() + " - " + atbashKey.getSecretKeyType().getAsymmetricPart();
        assertThat(data).isEqualTo("dc74e5f1-92a3-4f77-b824-d41db51d6ceb - RSA - PUBLIC");

    }

    @Test
    public void parseContent3() {

        List<AtbashKey> keys = reader.parseContent(null, null, data3);
        assertThat(keys).hasSize(1);

        AtbashKey atbashKey = keys.get(0);
        String data = atbashKey.getKeyId() + " - " + atbashKey.getSecretKeyType().getKeyType().getValue() + " - " + atbashKey.getSecretKeyType().getAsymmetricPart();
        assertThat(data).isEqualTo("demo - oct - SYMMETRIC");

    }

    @Test
    public void readResource() {
        Assertions.assertThrows(ResourceNotFoundException.class, () -> reader.readResource("./not-existent", new TestPasswordLookup()));
    }
}