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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.retriever.JWKSetRetriever;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.reflection.CDICheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Vetoed;
import java.io.IOException;
import java.net.URI;
import java.util.*;

@Vetoed
public class RemoteKeyManager extends AbstractKeyManager implements KeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteKeyManager.class);

    private Map<URI, JWKSetCache> remoteJWKSetCache = new HashMap<>();

    private JWKSetRetriever jwkSetRetriever = new JWKSetRetriever();

    private ValidateRemoteJWKSetURI validator = retrieveJWKSetURIValidator();

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<AtbashKey> result = new ArrayList<>();

        if (selectorCriteria.getJku() != null) {

            if (validator.validate(selectorCriteria.getJku())) {

                List<KeyFilter> filters = selectorCriteria.asKeyFilters();
                JWKSet jwkSet = getJWKSet(selectorCriteria.getJku());

                if (jwkSet != null) {
                    result = filterKeys(jwkSet.getAtbashKeys(), filters);
                }
            }
        }

        return result;
    }

    private JWKSet getJWKSet(URI jku) {
        JWKSetCache cache = remoteJWKSetCache.get(jku);
        if (cache == null) {
            cache = new JWKSetCache();
            remoteJWKSetCache.put(jku, cache);
        }
        JWKSet jwkSet = cache.get();
        if (jwkSet == null) {  // expired?
            try {
                cache.put(jwkSetRetriever.retrieveResource(jku.toURL()));
            } catch (IOException e) {
                LOGGER.warn(String.format("Retrieval of JWK from '%s' failed", jku.toASCIIString()));
            }
        }
        return cache.get();
    }

    @Override
    public String toString() {
        // For the startup logging.
        return "class " + RemoteKeyManager.class.getName();
    }

    private static ValidateRemoteJWKSetURI retrieveJWKSetURIValidator() {

        List<RemoteJWKSetURIValidator> validators = new ArrayList<>();

        ServiceLoader<RemoteJWKSetURIValidator> loader = ServiceLoader.load(RemoteJWKSetURIValidator.class);
        loader.forEach(validators::add);

        if (CDICheck.withinContainer()) {
            validators.addAll(CDIUtils.retrieveInstances(RemoteJWKSetURIValidator.class));
        }
        return new ValidateRemoteJWKSetURI(validators);
    }

}
