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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.PBKDF;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.impl.PRFParams;
import be.atbash.util.CDIUtils;
import be.atbash.util.reflection.CDICheck;

import javax.crypto.SecretKey;
import jakarta.enterprise.inject.Vetoed;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

@Vetoed // parent class is a CDI bean and otherwise this class would gives issues in CDI injection.
public class PasswordKeySelector extends KeySelector {

    private List<PasswordProviderForKey> providers = new ArrayList<>();

    public PasswordKeySelector(ListKeyManager listKeyManager) {
        super(listKeyManager);
    }

    public PasswordKeySelector() {

    }

    // FIXME How to define this KeySelector in a CDI environment.
    @Override
    public AtbashKey selectAtbashKey(SelectorCriteria selectorCriteria) {
        AtbashKey atbashKey = null;
        if (selectorCriteria.getPBE2Salt() != null && selectorCriteria.getAsymmetricPart() == AsymmetricPart.SYMMETRIC) {
            char[] password = getPassword(selectorCriteria.getId());
            if (password != null) {

                    SecretKey secretKey = PBKDF.deriveKey(password, selectorCriteria.getPBE2Salt().decode(), selectorCriteria.getPBE2Count(), PRFParams.resolve(selectorCriteria.getJweAlgorithm()));
                    atbashKey = new AtbashKey(selectorCriteria.getId(), secretKey);

            }

        }
        if (atbashKey == null) {
            atbashKey = super.selectAtbashKey(selectorCriteria);
        }
        return atbashKey;
    }

    private char[] getPassword(String kid) {
        loadProviders();
        Optional<char[]> result = providers.stream()
                .map(p -> p.getPassword(kid))
                .findAny();

        return result.orElse(null);
    }

    private synchronized void loadProviders() {
        if (providers.isEmpty() && CDICheck.withinContainer()) {
            providers = CDIUtils.retrieveInstances(PasswordProviderForKey.class);
        }
        if (providers.isEmpty()) {
            ServiceLoader<PasswordProviderForKey> services =
                    ServiceLoader.load(PasswordProviderForKey.class);
            services.iterator().forEachRemaining(p -> providers.add(p));
        }
    }
}
