package be.atbash.ee.security.octopus.keys.subview.model;

import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import javafx.stage.FileChooser;

import java.util.ArrayList;
import java.util.List;

public final class FileExtensionFilters {

    private static List<FileChooser.ExtensionFilter> filters;

    static {
        filters = new ArrayList<>();
        filters.add(new FileChooser.ExtensionFilter("JWK Files", convertExtensions(KeyResourceType.JWK)));
        filters.add(new FileChooser.ExtensionFilter("JWK Set Files", convertExtensions(KeyResourceType.JWKSET)));
        filters.add(new FileChooser.ExtensionFilter("PEM Files", convertExtensions(KeyResourceType.PEM)));
    }

    private static String[] convertExtensions(KeyResourceType keyResourceType) {
        String[] suffixes = keyResourceType.getSuffixes();
        String[] result = new String[suffixes.length];
        for (int i = 0; i < suffixes.length; i++) {
            result[i] = "*" + suffixes[i];
        }

        return result;
    }

    public static List<FileChooser.ExtensionFilter> getFilters() {
        return filters;
    }
}
