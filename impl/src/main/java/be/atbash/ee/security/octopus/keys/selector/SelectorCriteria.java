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
package be.atbash.ee.security.octopus.keys.selector;

import be.atbash.ee.security.octopus.keys.selector.filter.*;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.jwk.KeyType;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class SelectorCriteria {

    private String id;
    private SecretKeyType secretKeyType;
    private KeyType keyType;
    private AsymmetricPart asymmetricPart;
    private URI jku;
    private Object discriminator;

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

    public static Builder newBuilder() {
        return new Builder();
    }

    public static class Builder {
        private SelectorCriteria criteria = new SelectorCriteria();

        private Builder() {
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

        public SelectorCriteria build() {
            return criteria;
        }
    }
}
