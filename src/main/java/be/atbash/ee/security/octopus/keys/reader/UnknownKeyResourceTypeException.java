package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.util.exception.AtbashException;

/**
 *
 */

public class UnknownKeyResourceTypeException extends AtbashException {

    public UnknownKeyResourceTypeException(String path) {
        super(String.format("(JWT-???) Unable to determine Key resource type of %s", path));
    }
}
