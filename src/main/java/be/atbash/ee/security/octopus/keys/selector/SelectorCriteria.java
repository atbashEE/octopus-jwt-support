package be.atbash.ee.security.octopus.keys.selector;

import com.nimbusds.jose.jwk.KeyType;

/**
 *
 */

public class SelectorCriteria {

    private String id;
    private SecretKeyType secretKeyType;
    private KeyType keyType;
    private AsymmetricPart asymmetricPart;

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

        public SelectorCriteria build() {
            return criteria;
        }
    }
}
