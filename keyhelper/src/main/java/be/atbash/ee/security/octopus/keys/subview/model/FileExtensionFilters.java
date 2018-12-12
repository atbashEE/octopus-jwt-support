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
