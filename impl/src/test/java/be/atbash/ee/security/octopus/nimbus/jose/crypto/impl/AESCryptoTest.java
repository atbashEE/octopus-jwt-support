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
package be.atbash.ee.security.octopus.nimbus.jose.crypto.impl;


import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import org.junit.jupiter.api.Test;

import org.assertj.core.api.Assertions;


/**
 * Tests static AES crypto provider constants and methods.
 * <p>
 * Based on code by Vladimir Dzhuvinov
 */
public class AESCryptoTest  {


	@Test
	public void testClassAlgorithmSupport() {

		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).hasSize(6);

		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A128KW);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A192KW);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A256KW);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A128GCMKW);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A192GCMKW);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ALGORITHMS).contains(JWEAlgorithm.A256GCMKW);
	}

	@Test
	public void testClassEncryptionMethodSupport() {

		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).hasSize(6);

		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A128CBC_HS256);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A192CBC_HS384);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A256CBC_HS512);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A128GCM);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A192GCM);
		Assertions.assertThat(AESCryptoProvider.SUPPORTED_ENCRYPTION_METHODS).contains(EncryptionMethod.A256GCM);
	}
}
