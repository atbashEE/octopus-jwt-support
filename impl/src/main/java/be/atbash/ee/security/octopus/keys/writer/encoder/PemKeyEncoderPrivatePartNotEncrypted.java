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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;

/**
 *
 */

public class PemKeyEncoderPrivatePartNotEncrypted implements KeyEncoder {

    // FIXME Left over of initial version to define header. But probably not needed.
    // So also no specific versions for RSA en EC required.
    private String keyType;

    public PemKeyEncoderPrivatePartNotEncrypted(String keyType) {
        this.keyType = keyType;
    }

    @Override
    public byte[] encodeKey(AtbashKey atbashKey, KeyEncoderParameters parameters) throws IOException {
        StringWriter out = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(out);

        //pemWriter.writeObject(new PemObject(keyType + " PRIVATE KEY", atbashKey.getKey().getEncoded()));
        pemWriter.writeObject(atbashKey.getKey());

        pemWriter.close();

        return out.toString().getBytes("UTF-8");
    }
}
