/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.util.resource.ResourceUtil;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 *
 */

public class KeyReaderTester {

    public static void main(String[] args) throws IOException, OperatorCreationException {

        KeyReader keyReader = new KeyReader();
        List<AtbashKey> keys = keyReader.readKeyResource(ResourceUtil.CLASSPATH_PREFIX + "rsa.jwk", new TestPasswordLookup("atbash".toCharArray()));
        for (AtbashKey key : keys) {
            System.out.println("XXXXX");
            System.out.println("Key Id " + key.getKeyId());
            System.out.println("Key Type " + key.getSecretKeyType().getKeyType() + " - " + key.getSecretKeyType().getAsymmetricPart());
            System.out.println("Key" + key.getKey());

            if (key.getSecretKeyType().getAsymmetricPart() == AsymmetricPart.PUBLIC) {
                RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) key.getKey())
                        .keyID("xx")
                        .build();
                System.out.println(rsaKey.toJSONObject().toJSONString());
            }
        }

        /*
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(System.out));
        writer.writeObject(keys.get(0).getKey());
        writer.close();
*/
        // construct encryptor builder to encrypt the private key
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
        encryptorBuilder.setRandom(new SecureRandom());
        encryptorBuilder.setPasssword("password".toCharArray());
        OutputEncryptor encryptor = encryptorBuilder.build();

        // construct object to create the PKCS8 object from the private key and encryptor
        JcaPKCS8Generator pkcsGenerator = new JcaPKCS8Generator((PrivateKey) keys.get(0).getKey(), encryptor);
        PemObject pemObj = pkcsGenerator.generate();
        JcaPEMWriter pemWriter = new JcaPEMWriter(new PrintWriter(System.out));

        pemWriter.writeObject(pemObj);

        pemWriter.close();
    }

    private static class TestPasswordLookup implements KeyResourcePasswordLookup {
        // FIXME Use be.atbash.ee.security.octopus.keys.TestPasswordLookup
        private char[] password;

        public TestPasswordLookup(char[] password) {

            this.password = password;
        }

        @Override
        public char[] getResourcePassword(String path) {
            return password;
        }

        @Override
        public char[] getKeyPassword(String path, String keyId) {
            return new char[0];
        }
    }
}
