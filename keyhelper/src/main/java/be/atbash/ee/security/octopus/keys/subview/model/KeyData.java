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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.PasswordDialog;
import be.atbash.ee.security.octopus.keys.reader.KeyReader;
import be.atbash.ee.security.octopus.keys.reader.password.KeyResourcePasswordLookup;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 *
 */

public class KeyData {

    private List<AtbashKey> keys;
    private File currentFile;
    private BooleanProperty changed;
    private List<AtbashKeyItem> keyItems;
    private KeyResourcePasswordLookup passwordLookup;

    public KeyData() {
        changed = new SimpleBooleanProperty(false);
        keyItems = new ArrayList<>();
        passwordLookup = new PasswordDialog();
    }

    public void onNewFile() {
        currentFile = null;
        keys = new ArrayList<>();
        changed.setValue(true);

        keyItems = new ArrayList<>();
        changed.setValue(false);
    }

    public void onOpenFile(File selectedFile) {
        keys = new ArrayList<>();
        KeyReader keyReader = new KeyReader();
        add(keyReader.readKeyResource(selectedFile.getAbsolutePath(), passwordLookup));

        currentFile = selectedFile;
        changed.setValue(true);
    }

    public List<AtbashKeyItem> getItems() {
        return keyItems;
    }

    public void add(List<AtbashKey> keys) {
        this.keys.addAll(keys);
        keys.forEach(this::onAddKey);
        changed.setValue(true);
    }

    private void onAddKey(AtbashKey atbashKey) {
        AtbashKeyItem item = new AtbashKeyItem();
        item.kidProperty().setValue(atbashKey.getKeyId());
        item.setKeyType(atbashKey.getSecretKeyType().getKeyType().getValue());
        item.setAsymmetricPart(atbashKey.getSecretKeyType().getAsymmetricPart());

        keyItems.add(item);

        new KidChangeListener(atbashKey, item.kidProperty());
    }


    public void removeKey(AtbashKeyItem item) {
        Optional<AtbashKey> key = findKey(item);
        if (key.isPresent()) {
            keys.remove(key.get());
            keyItems.remove(item);
        }

    }

    public BooleanProperty changedProperty() {
        return changed;
    }

    public boolean hasFileName() {
        return currentFile != null;
    }

    public List<AtbashKey> getSelectedKeys() {
        return keyItems.stream()
                .filter(AtbashKeyItem::isSelected)
                .map(this::findKey)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());

    }

    private Optional<AtbashKey> findKey(AtbashKeyItem item) {
        return keys.stream().filter(key -> key.isMatch(item.kidProperty().getValue(), item.getAsymmetricPart()))
                .findAny();
    }

    private class KidChangeListener implements ChangeListener<String> {

        KidChangeListener(AtbashKey atbashKey, StringProperty kidProperty) {
            kidProperty.addListener((observable, oldValue, newValue) -> {
                keys.remove(atbashKey);
                AtbashKey.AtbashKeyBuilder builder = new AtbashKey.AtbashKeyBuilder();
                keys.add(builder.withKeyId(newValue).withKey(atbashKey.getKey()).build());
            });
        }

        @Override
        public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {

        }
    }
}
