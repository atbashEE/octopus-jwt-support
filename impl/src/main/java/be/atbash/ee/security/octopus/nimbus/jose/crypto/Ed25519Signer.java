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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.KeyTypeException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.EdDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetKeyPair;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSSigner;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;


/**
 * Ed25519 signer of {@link be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject JWS objects}.
 * Expects an {@link OctetKeyPair} with {@code "crv"} Ed25519.
 * Uses the Edwards-curve Digital Signature Algorithm (EdDSA).
 *
 * <p>See <a href="https://tools.ietf.org/html/rfc8037">RFC 8037</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithm:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#EdDSA}
 * </ul>
 *
 * <p>with the following curve:
 *
 * <ul>
 *     <li>{@link Curve#Ed25519}
 * </ul>
 *
 * Based on code by  Tim McLean
 */
public class Ed25519Signer extends EdDSAProvider implements JWSSigner {


	private final org.bouncycastle.crypto.signers.Ed25519Signer signer;


	/**
	 * Creates a new Ed25519 signer.
	 *
	 * @param privateKey The private key. Must be non-{@code null}, and must
	 *                   be of type Ed25519 ({@code "crv": "Ed25519"}).
	 */
	public Ed25519Signer(BCEdDSAPrivateKey privateKey) {

		if (!Curve.Ed25519.getName().equals(privateKey.getAlgorithm())) {
			throw new JOSEException("Ed25519Signer only supports OctetKeyPairs with crv=Ed25519");
		}

		signer = new org.bouncycastle.crypto.signers.Ed25519Signer();
		CipherParameters parameters = new Ed25519PrivateKeyParameters(getD(privateKey), 0);
		signer.init(true, parameters);

	}

	/**
	 * Creates a new Ed25519 signer.
	 *
	 * @param atbashKey The private key. Must be non-{@code null}, and must
	 *                  be of type Ed25519 ({@code "crv": "Ed25519"}).
	 */
	public Ed25519Signer(AtbashKey atbashKey) {

		this(getPrivateKey(atbashKey));

    }

    private static BCEdDSAPrivateKey getPrivateKey(AtbashKey atbashKey) {
        if (atbashKey.getSecretKeyType().getKeyType() != KeyType.OKP) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        if (atbashKey.getSecretKeyType().getAsymmetricPart() != AsymmetricPart.PRIVATE) {
            throw new KeyTypeException(ECPrivateKey.class);
        }
        return (BCEdDSAPrivateKey) atbashKey.getKey();
    }

    private byte[] getD(BCEdDSAPrivateKey privateKey) {
		// The next code statements are required to get access to the x and d values of the private Key.
		// BouncyCastle should have support for it!
		ASN1InputStream stream = new ASN1InputStream(privateKey.getEncoded());
		ASN1Primitive primitive;
		try {
			primitive = stream.readObject();
		} catch (IOException e) {
			throw new AtbashUnexpectedException(e);
		}
		// [1, [1.3.101.112], #0420f615acda8498cfc96c45c00f80e2438aa490f9e8b1201320aba968d7e750095d, [1]#00f2c6678839670f1abaed87171ac938122cd4c62e4c6d24c7620f63da893ab682]
		DLSequence sequence = (DLSequence) primitive;

		ASN1Encodable item1 = sequence.getObjectAt(2);
		DEROctetString privateBytes = (DEROctetString) item1;

		byte[] dBytes = new byte[Ed25519.SECRET_KEY_SIZE];
		System.arraycopy(privateBytes.getOctets(), 2, dBytes, 0, Ed25519.SECRET_KEY_SIZE);
		return dBytes;
	}


	@Override
	public Base64URLValue sign(JWSHeader header, byte[] signingInput) {

		// Check alg field in header
		JWSAlgorithm alg = header.getAlgorithm();
		if (!JWSAlgorithm.EdDSA.equals(alg)) {
			throw new JOSEException("Ed25519Signer requires alg=EdDSA in JWSHeader");
		}

		byte[] jwsSignature;

		signer.update(signingInput, 0, signingInput.length);
		jwsSignature = signer.generateSignature();

		signer.reset();

		return Base64URLValue.encode(jwsSignature);
	}
}
