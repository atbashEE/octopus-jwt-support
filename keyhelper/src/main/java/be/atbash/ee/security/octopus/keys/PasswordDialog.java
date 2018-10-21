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
package be.atbash.ee.security.octopus.keys;

import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import javafx.scene.control.TextInputDialog;

import java.util.Optional;

public class PasswordDialog implements KeyResourcePasswordLookup {

    @Override
    public char[] getResourcePassword(String path) {
        return askPassword("Password for file " + path).toCharArray();
    }

    @Override
    public char[] getKeyPassword(String path, String keyId) {
        return askPassword("Password for key " + keyId).toCharArray();
    }

    private String askPassword(String text) {

        // FIXME use some password dialog??
        TextInputDialog dialog = new TextInputDialog("");
        dialog.setTitle("Text Input Dialog");
        dialog.setHeaderText(text);
        dialog.setContentText("Please enter the password:");

        // Traditional way to get the response value.
        Optional<String> result = dialog.showAndWait();
        return result.orElse("");
    }
}
