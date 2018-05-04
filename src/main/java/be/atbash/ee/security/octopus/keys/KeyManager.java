package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;

import java.util.List;

/**
 *
 */

public interface KeyManager {

    List<AtbashKey> retrieveKeys(List<KeyFilter> filters);
}
