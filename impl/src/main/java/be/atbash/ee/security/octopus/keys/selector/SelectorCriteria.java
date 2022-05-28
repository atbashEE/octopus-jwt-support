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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.selector.filter.*;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyType;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@PublicAPI
public class SelectorCriteria {

    private String id;
    private SecretKeyType secretKeyType;
    private KeyType keyType;
    private AsymmetricPart asymmetricPart;
    private URI jku;
    private Object discriminator;
    // The following 3 properties are there to support password based encryption.
    // TODO Verify if this is a proper solution and that it still matches the idea of criteria for selecting the appropriate key.
    private Base64URLValue PBE2Salt;
    private int PBE2Count;
    private JWEAlgorithm jweAlgorithm;

    private SelectorCriteria() {
    }

    public String getId() {
        return id;
    }

    public SecretKeyType getSecretKeyType() {
        return secretKeyType;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public AsymmetricPart getAsymmetricPart() {
        return asymmetricPart;
    }

    public URI getJku() {
        return jku;
    }

    public Object getDiscriminator() {
        return discriminator;
    }

    public Base64URLValue getPBE2Salt() {
        return PBE2Salt;
    }

    public int getPBE2Count() {
        return PBE2Count;
    }

    public JWEAlgorithm getJweAlgorithm() {
        return jweAlgorithm;
    }

    public List<KeyFilter> asKeyFilters() {
        List<KeyFilter> result = new ArrayList<>();
        if (StringUtils.hasText(id)) {
            result.add(new IdKeyFilter(id));
        }
        if (secretKeyType != null) {
            result.add(new SecretKeyTypeKeyFilter(secretKeyType));
        }
        if (keyType != null) {
            result.add(new KeyTypeKeyFilter(keyType));
        }
        if (asymmetricPart != null) {
            result.add(new AsymmetricPartKeyFilter(asymmetricPart));
        }
        return result;
    }

    @Override
    public String toString() {

        StringBuilder result = new StringBuilder();
        result.append("KeySelectorCriteria{");
        for (KeyFilter keyFilter : asKeyFilters()) {
            result.append("\n     ").append(keyFilter.describe());
        }
        result.append("\n}");
        return result.toString();
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(SelectorCriteria selectorCriteria) {
        return new Builder(selectorCriteria);
    }

    @PublicAPI
    public static class Builder {
        private final SelectorCriteria criteria = new SelectorCriteria();

        private Builder() {
        }

        private Builder(SelectorCriteria selectorCriteria) {
            criteria.id = selectorCriteria.id;
            criteria.secretKeyType = selectorCriteria.secretKeyType;
            criteria.keyType = selectorCriteria.keyType;
            criteria.asymmetricPart = selectorCriteria.asymmetricPart;
            criteria.jku = selectorCriteria.jku;
            criteria.discriminator = selectorCriteria.discriminator;
            criteria.PBE2Salt = selectorCriteria.PBE2Salt;
            criteria.PBE2Count = selectorCriteria.PBE2Count;
            criteria.jweAlgorithm = selectorCriteria.jweAlgorithm;
        }

        public Builder withId(String id) {
            criteria.id = id;
            return this;
        }

        public Builder withSecretKeyType(SecretKeyType secretKeyType) {
            criteria.secretKeyType = secretKeyType;
            return this;
        }

        public Builder withKeyType(KeyType keyType) {
            criteria.keyType = keyType;
            return this;
        }

        public Builder withAsymmetricPart(AsymmetricPart asymmetricPart) {
            criteria.asymmetricPart = asymmetricPart;
            return this;
        }

        public Builder withJKU(URI jku) {
            criteria.jku = jku;
            return this;
        }

        public Builder withDiscriminator(Object discriminator) {
            criteria.discriminator = discriminator;
            return this;
        }

        public Builder withPBE2Salt(Base64URLValue pbe2Salt) {
            criteria.PBE2Salt = pbe2Salt;
            return this;
        }

        public Builder withPBE2Count(int count) {
            criteria.PBE2Count = count;
            return this;
        }

        public Builder withJWEAlgorithm(JWEAlgorithm jweAlgorithm) {
            criteria.jweAlgorithm = jweAlgorithm;
            return this;
        }

        public SelectorCriteria build() {
            return criteria;
        }
    }
}
