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


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.IntegerUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the Concatenation KDF.
 *
 * Based on code by Vladimir Dzhuvinov
 */
public class ConcatKDFTest {
	
	@Test
	public void testComposeOtherInfo() {
		
		// From http://tools.ietf.org/html/rfc7518#appendix-C
		
		String algId = "A128GCM";
		String producer = "Alice";
		String consumer = "Bob";
		int pubInfo = 128;
		
		byte[] otherInfo = ConcatKDF.composeOtherInfo(
			ConcatKDF.encodeStringData(algId),
			ConcatKDF.encodeStringData(producer),
			ConcatKDF.encodeStringData(consumer),
			ConcatKDF.encodeIntData(pubInfo),
			ConcatKDF.encodeNoData());
		
		byte[] expected = {
			(byte) 0, (byte) 0, (byte) 0, (byte) 7, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 71, (byte) 67, (byte) 77, (byte) 0, (byte) 0, (byte) 0, (byte) 5, (byte) 65,
			(byte) 108, (byte) 105, (byte) 99, (byte) 101, (byte) 0, (byte) 0, (byte) 0, (byte) 3,
			(byte) 66, (byte) 111, (byte) 98, (byte) 0, (byte) 0, (byte) 0, (byte) 128
		};

		assertThat(Arrays.equals(expected, otherInfo)).isTrue();
	}

	@Test
	public void testECDHVector() {

		// From http://tools.ietf.org/html/rfc7518#appendix-C

		byte[] Z = {
				(byte) 158, (byte) 86, (byte) 217, (byte) 29, (byte) 129, (byte) 113, (byte) 53, (byte) 211,
				(byte) 114, (byte) 131, (byte) 66, (byte) 131, (byte) 191, (byte) 132, (byte) 38, (byte) 156,
				(byte) 251, (byte) 49, (byte) 110, (byte) 163, (byte) 218, (byte) 128, (byte) 106, (byte) 72,
				(byte) 246, (byte) 218, (byte) 167, (byte) 121, (byte) 140, (byte) 254, (byte) 144, (byte) 196
		};

		int keyLength = 128;
		String algId = "A128GCM";
		String producer = "Alice";
		String consumer = "Bob";
		int pubInfo = 128;
		
		ConcatKDF concatKDF = new ConcatKDF("SHA-256");
		
		assertThat(concatKDF.getHashAlgorithm()).isEqualTo("SHA-256");
		
		SecretKey derivedKey = concatKDF.deriveKey(
			new SecretKeySpec(Z, "AES"),
			keyLength,
			ConcatKDF.encodeStringData(algId),
			ConcatKDF.encodeStringData(producer),
			ConcatKDF.encodeStringData(consumer),
			ConcatKDF.encodeIntData(pubInfo),
			ConcatKDF.encodeNoData());
		
		assertThat(derivedKey.getEncoded().length * 8).isEqualTo(128);
		
		byte[] expectedDerivedKey = {
			(byte) 86, (byte) 170, (byte) 141, (byte) 234, (byte) 248, (byte) 35, (byte) 109, (byte) 32,
			(byte) 92, (byte) 34, (byte) 40, (byte) 205, (byte) 113, (byte) 167, (byte) 16, (byte) 26};

		assertThat(Arrays.equals(expectedDerivedKey, derivedKey.getEncoded())).isTrue();
	}

	@Test
	public void testComputeDigestCycles1() {
		
		int digestLength = 256;
		int keyLength = 521;
		
		assertThat(ConcatKDF.computeDigestCycles(digestLength, keyLength)).isEqualTo(3);
	}

	@Test
	public void testComputeDigestCycles2() {
		
		int digestLength = 256;
		int keyLength = 128;
		
		assertThat(ConcatKDF.computeDigestCycles(digestLength, keyLength)).isEqualTo(1);
	}

	@Test
	public void testEncodeNoData() {
		
		byte[] out = ConcatKDF.encodeNoData();
		
		assertThat(out.length).isEqualTo(0);
	}

	@Test
	public void testEncodeIntData() {
		
		byte[] out = ConcatKDF.encodeIntData(1);

		assertThat(Arrays.equals(new byte[]{0, 0, 0, 1}, out)).isTrue();
	}

	@Test
	public void testEncodeStringData() {
		
		byte[] out = ConcatKDF.encodeStringData("Hello world!");
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertThat(Arrays.equals(IntegerUtils.toBytes("Hello world!".length()), length)).isTrue();
		
		byte[] chars = ByteUtils.subArray(out, 4, out.length - 4);
		assertThat(Arrays.equals("Hello world!".getBytes(StandardCharsets.UTF_8), chars)).isTrue();
	}

	@Test
	public void testEncodeDataWithLength() {
		
		byte[] out = ConcatKDF.encodeDataWithLength(new byte[]{0, 1, 2, 3});
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertThat(Arrays.equals(IntegerUtils.toBytes(4), length)).isTrue();
		
		byte[] data = ByteUtils.subArray(out, 4, out.length - 4);
		assertThat(Arrays.equals(new byte[]{0, 1, 2, 3}, data)).isTrue();
	}

	@Test
	public void testEncodeBase64URLDataWithLength() {
		
		byte[] out = ConcatKDF.encodeDataWithLength(Base64URLValue.encode(new byte[]{0, 1, 2, 3}));
		
		byte[] length = ByteUtils.subArray(out, 0, 4);
		assertThat(Arrays.equals(IntegerUtils.toBytes(4), length)).isTrue();
		
		byte[] data = ByteUtils.subArray(out, 4, out.length - 4);
		assertThat(Arrays.equals(new byte[]{0, 1, 2, 3}, data)).isTrue();
	}

	@Test
	public void testKeyDerivation()
		throws Exception {
		
		ConcatKDF concatKDF = new ConcatKDF("SHA-256");
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey sharedKey = keyGenerator.generateKey();
		
		SecretKey derivedKey128 = concatKDF.deriveKey(sharedKey, 128, null);
		assertThat(ByteUtils.bitLength(derivedKey128.getEncoded().length)).isEqualTo(128);
		
		SecretKey derivedKey256 = concatKDF.deriveKey(sharedKey, 256, null);
		assertThat(ByteUtils.bitLength(derivedKey256.getEncoded().length)).isEqualTo(256);
	}

	@Test
    public void testComputeDigestCycles() {
		
		assertThat(ConcatKDF.computeDigestCycles(256, 128)).isEqualTo(1);
		assertThat(ConcatKDF.computeDigestCycles(384, 128)).isEqualTo(1);
		assertThat(ConcatKDF.computeDigestCycles(512, 128)).isEqualTo(1);
		
		assertThat(ConcatKDF.computeDigestCycles(256, 256)).isEqualTo(1);
		assertThat(ConcatKDF.computeDigestCycles(384, 256)).isEqualTo(1);
		assertThat(ConcatKDF.computeDigestCycles(512, 256)).isEqualTo(1);
		
		assertThat(ConcatKDF.computeDigestCycles(256, 384)).isEqualTo(2);
		assertThat(ConcatKDF.computeDigestCycles(384, 384)).isEqualTo(1);
		assertThat(ConcatKDF.computeDigestCycles(512, 384)).isEqualTo(1);
		
		assertThat(ConcatKDF.computeDigestCycles(256, 512)).isEqualTo(2);
		assertThat(ConcatKDF.computeDigestCycles(384, 512)).isEqualTo(2);
		assertThat(ConcatKDF.computeDigestCycles(512, 512)).isEqualTo(1);
	}
}