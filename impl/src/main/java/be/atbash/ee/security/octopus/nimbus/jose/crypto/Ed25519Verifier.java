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
package be.atbash.ee.security.octopus.nimbus.jose.crypto;


import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.CriticalHeaderParamsDeferral;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.EdDSAProvider;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.ee.security.octopus.nimbus.jwk.OctetKeyPair;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSVerifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import java.io.IOException;
import java.util.Set;


/**
 * Ed25519 verifier of {@link com.nimbusds.jose.JWSObject JWS objects}.
 * Expects a public {@link OctetKeyPair} with {@code "crv"} Ed25519.
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
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#EdDSA}
 * </ul>
 *
 * <p>with the following curve:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.Curve#Ed25519}
 * </ul>
 *
 * @author Tim McLean
 * @version 2018-07-11
 */
public class Ed25519Verifier extends EdDSAProvider implements JWSVerifier {


	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	private final BCEdDSAPublicKey publicKey;


	private final org.bouncycastle.crypto.signers.Ed25519Signer verifier;


	/**
	 * Creates a new Ed25519 verifier.
	 *
	 * @param publicKey The public Ed25519 key. Must not be {@code null}.
	 * @throws JOSEException If the key subtype is not supported
	 */
	public Ed25519Verifier(BCEdDSAPublicKey publicKey)
			throws JOSEException {

		this(publicKey, null);
	}


	/**
	 * Creates a Ed25519 verifier.
	 *
	 * @param publicKey      The public Ed25519 key. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 * @throws JOSEException If the key subtype is not supported.
	 */
	public Ed25519Verifier(BCEdDSAPublicKey publicKey, Set<String> defCritHeaders)
			throws JOSEException {

		super();

		if (!Curve.Ed25519.getName().equals(publicKey.getAlgorithm())) {
			throw new JOSEException("Ed25519Verifier only supports OctetKeyPairs with crv=Ed25519");
		}

		this.publicKey = publicKey;
		verifier = new org.bouncycastle.crypto.signers.Ed25519Signer();
		CipherParameters parameters = new Ed25519PublicKeyParameters(getDecodedX(), 0);
		verifier.init(false, parameters);
		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}

	private byte[] getDecodedX() {
		ASN1InputStream stream = new ASN1InputStream(publicKey.getEncoded());
		ASN1Primitive primitive = null;
		try {
			primitive = stream.readObject();
		} catch (IOException e) {
			throw new AtbashUnexpectedException(e);
		}
		//[[1.3.101.112], #032100238DBA14FF77991890E136DAF5B0844C1AB096E513A361F0F26FCEDCD7E9E7DA]
		DLSequence sequence = (DLSequence) primitive;

		ASN1Encodable x1 = sequence.getObjectAt(1);
		DERBitString publicBytes = (DERBitString) x1;

		return publicBytes.getOctets();
	}

	@Override
	public boolean verify(JWSHeader header,
						  byte[] signedContent,
						  Base64URLValue signature)
			throws JOSEException {

		// Check alg field in header
		JWSAlgorithm alg = header.getAlgorithm();
		if (!JWSAlgorithm.EdDSA.equals(alg)) {
			throw new JOSEException("Ed25519Verifier requires alg=EdDSA in JWSHeader");
		}

		// Check for unrecognized "crit" properties
		if (!critPolicy.headerPasses(header)) {
			return false;
		}

		byte[] jwsSignature = signature.decode();


		verifier.update(signedContent, 0, signedContent.length);
		boolean result = verifier.verifySignature(jwsSignature);
		verifier.reset();
		return result;

	}
}
