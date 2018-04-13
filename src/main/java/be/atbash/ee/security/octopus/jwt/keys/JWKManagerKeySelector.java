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
package be.atbash.ee.security.octopus.jwt.keys;

import be.atbash.ee.security.octopus.jwk.JWKManager;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.SecretJWK;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.Key;

/**
 *
 */
@ApplicationScoped
public class JWKManagerKeySelector implements KeySelector {

    @Inject
    private JWKManager jwkManager;

    @Override
    public <T extends Key> T selectSecretKey(String keyId) {
        if (jwkManager.existsApiKey(keyId)) {
            JWK jwk = jwkManager.getJWKForApiKey(keyId);

            try {
                if (jwk instanceof SecretJWK) {
                    return (T) ((SecretJWK) jwk).toSecretKey();
                }
                if (jwk instanceof AsymmetricJWK) {
                    return (T) ((AsymmetricJWK) jwk).toPublicKey();
                }
                throw new UnsupportedOperationException("JWK not supported " + jwk.getClass().getName());
            } catch (JOSEException e) {
                throw new AtbashUnexpectedException(e);
            }
        }
        return null;
    }
}
