package be.atbash.ee.security.octopus.config;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PemKeyEncryptionTest {

    @Test
    public void parse() {
        PemKeyEncryption value = PemKeyEncryption.parse("PKCS8");
        assertThat(value).isEqualTo(PemKeyEncryption.PKCS8);
    }

    @Test
    public void parse_modified() {
        PemKeyEncryption value = PemKeyEncryption.parse(" pkcs#1  ");
        assertThat(value).isEqualTo(PemKeyEncryption.PKCS1);
    }

    @Test
    public void parse_empty() {
        PemKeyEncryption value = PemKeyEncryption.parse("  ");
        assertThat(value).isNull();
    }

    @Test
    public void parse_null() {
        PemKeyEncryption value = PemKeyEncryption.parse(null);
        assertThat(value).isNull();
    }
}