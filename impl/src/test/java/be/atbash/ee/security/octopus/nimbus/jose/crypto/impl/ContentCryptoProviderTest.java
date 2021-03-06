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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jose.KeyLengthException;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWECryptoParts;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the content encryption / decryption provider.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class ContentCryptoProviderTest {

	@Test
	public void testCompatibleEncryptionMethods() {

		// 128 bit cek
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128)).contains(EncryptionMethod.A128GCM);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128).size()).isEqualTo(1);

		// 192 bit cek
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192)).contains(EncryptionMethod.A192GCM);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192).size()).isEqualTo(1);

		// 256 bit cek
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256)).contains(EncryptionMethod.A256GCM);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256)).contains(EncryptionMethod.A128CBC_HS256);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).size()).isEqualTo(2);

		// 384 bit cek
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384)).contains(EncryptionMethod.A192CBC_HS384);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384).size()).isEqualTo(1);

		// 512 bit cek
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512)).contains(EncryptionMethod.A256CBC_HS512);
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).size()).isEqualTo(1);

		// Total
		assertThat(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.size()).isEqualTo(5);
	}

	@Test
	public void test_A256CBC_HS512() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		byte[] clearText = "Hello world!".getBytes(StandardCharsets.UTF_8);
		byte[] cekBytes = new byte[64];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		Base64URLValue encryptedKey = null;

		JWECryptoParts jweParts = ContentCryptoProvider.encrypt(
				header,
				clearText,
				cek,
				encryptedKey);

		assertThat(Arrays.equals(clearText, ContentCryptoProvider.decrypt(
				header,
				jweParts.getInitializationVector(),
				jweParts.getCipherText(),
				jweParts.getAuthenticationTag(),
				cek))).isTrue();
	}

	@Test
	public void test_A256CBC_HS512_cekTooShort() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		byte[] clearText = "Hello world!".getBytes(StandardCharsets.UTF_8);
		byte[] cekBytes = new byte[32];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		Base64URLValue encryptedKey = null;

		KeyLengthException e = Assertions.assertThrows(KeyLengthException.class,
				() -> ContentCryptoProvider.encrypt(
						header,
						clearText,
						cek,
						encryptedKey));

		assertThat(e.getMessage()).isEqualTo("The Content Encryption Key (CEK) length for A256CBC-HS512 must be 512 bits");
	}

	@Test
	public void test_A256GCM_cekTooShort() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		byte[] clearText = "Hello world!".getBytes(StandardCharsets.UTF_8);
		byte[] cekBytes = new byte[16];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		Base64URLValue encryptedKey = null;

		KeyLengthException e = Assertions.assertThrows(KeyLengthException.class,
				() -> ContentCryptoProvider.encrypt(
						header,
						clearText,
						cek,
						encryptedKey
				));


		assertThat(e.getMessage()).isEqualTo("The Content Encryption Key (CEK) length for A256GCM must be 256 bits");

	}

	@Test
	public void testKeyGen() {

		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A128GCM).getEncoded().length).isEqualTo(ByteUtils.byteLength(128));
		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A192GCM).getEncoded().length).isEqualTo(ByteUtils.byteLength(192));
		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A256GCM).getEncoded().length).isEqualTo(ByteUtils.byteLength(256));
		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A128CBC_HS256).getEncoded().length).isEqualTo(ByteUtils.byteLength(256));
		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A192CBC_HS384).getEncoded().length).isEqualTo(ByteUtils.byteLength(384));
		assertThat(ContentCryptoProvider.generateCEK(EncryptionMethod.A256CBC_HS512).getEncoded().length).isEqualTo(ByteUtils.byteLength(512));

	}
}
