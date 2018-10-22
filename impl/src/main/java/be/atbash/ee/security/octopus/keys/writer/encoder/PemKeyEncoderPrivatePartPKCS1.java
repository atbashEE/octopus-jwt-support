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
import be.atbash.util.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 *
 */

public class PemKeyEncoderPrivatePartPKCS1 implements KeyEncoder {

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        // sez https://www.javatips.net/api/org.bouncycastle.util.io.pem.pemobjectgenerator
        /*
        @param encryptionAlg encryption algorithm to be used.
	 * Use null if output must not be encrypted.
                * For PKCS8 output see {@link JceOpenSSLPKCS8EncryptorBuilder} constants for available names.
	 * For the legacy openssl format, one can use the
                * algorithm names composed from 3 parts glued with hyphen. The first part determines algorithm,
	 * one of AES, DES, BF and RC2. The second part determines key bits and is used for AES and
	 * optionally for RC2. For AES it is possible to use values
	 * 128, 192 and 256. For RC2 64, 40 can be used or nothing - then value 128 is used.
	 * The last part determines the block mode: CFB, ECB, OFB, EDE and CBC. Additionally EDE3
	 * can be used in combination with DES to use DES3 with EDE. Examples:
	 * AES-192-ECB or DES-EDE3.
                */
        String encryptionAlg = parameters.getValue("PKCS1.encryption", String.class);
        JcaMiscPEMGenerator generator;
        if (StringUtils.isEmpty(encryptionAlg)) {
            // No encryption, Unencrypted format (SSLeay format?)
            generator = new JcaMiscPEMGenerator(atbashKey.getKey());
        } else {
            JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(encryptionAlg);
            builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            builder.setSecureRandom(new SecureRandom());
            PEMEncryptor encryptor = builder.build(parameters.getKeyPassword());
            generator = new JcaMiscPEMGenerator(atbashKey.getKey(), encryptor);
        }

        StringWriter out = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(out);

        pemWriter.writeObject(generator);

        pemWriter.close();

        return out.toString().getBytes(StandardCharsets.UTF_8);
    }
}
