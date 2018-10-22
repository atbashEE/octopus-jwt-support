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
package be.atbash.ee.security.octopus.keys.writer.encoder;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;

/**
 *
 */

public class PemKeyEncoderPrivatePartPKCS8 implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        // construct encryptor builder to encrypt the private key
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC);
        encryptorBuilder.setRandom(new SecureRandom());
        encryptorBuilder.setPasssword(parameters.getKeyPassword());
        OutputEncryptor encryptor;
        try {
            encryptor = encryptorBuilder.build();
        } catch (OperatorCreationException e) {
            throw new AtbashUnexpectedException(e);
        }

        // construct object to create the PKCS8 object from the private key and encryptor
        JcaPKCS8Generator pkcsGenerator = new JcaPKCS8Generator((PrivateKey) atbashKey.getKey(), encryptor);
        PemObject pemObj = pkcsGenerator.generate();

        StringWriter out = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(out);

        pemWriter.writeObject(pemObj);

        pemWriter.close();

        return out.toString().getBytes(StandardCharsets.UTF_8);
    }
}
