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
package be.atbash.ee.security.octopus.keys.subview;

import be.atbash.ee.security.octopus.ScreenArtifacts;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.reader.KeyResourceType;
import be.atbash.ee.security.octopus.keys.subview.model.AtbashKeyItem;
import be.atbash.ee.security.octopus.keys.subview.model.KeyData;
import be.atbash.ee.security.octopus.keys.writer.KeyWriter;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import jfxtras.scene.control.ToggleGroupValue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static be.atbash.ee.security.octopus.ScreenArtifacts.viewTitleFont;

public class SaveTypeView extends SubView {

    private KeyData keyData;
    private ToggleGroupValue fileTypeToggleGroupValue;
    private StringProperty fileNameProperty;
    private BooleanProperty fileNameSelectedProperty;

    protected SaveTypeView(Stage primaryStage, BorderPane rootPane, KeyData keyData) {
        super(primaryStage, rootPane);
        this.keyData = keyData;
    }

    @Override
    public void initialize() {
        List<KeyResourceType> resourceTypes = definePossibleKeyResourceTypes();
        defineSubView(resourceTypes);
    }

    private List<KeyResourceType> definePossibleKeyResourceTypes() {
        List<KeyResourceType> result = new ArrayList<>();

        result.add(KeyResourceType.JWKSET); // JWKSet always supported.
        long selectedCount = keyData.getItems().stream()
                .filter(AtbashKeyItem::isSelected)
                .count();

        if (selectedCount == 1) {
            result.add(KeyResourceType.JWK);
        }

        return result;
    }

    private void defineSubView(List<KeyResourceType> resourceTypes) {
        VBox mainView = new VBox();
        mainView.setPadding(new Insets(10, 10, 10, 10));

        Text title = new Text("Cryptographic keys");
        title.setFont(viewTitleFont);

        VBox toggleGroupBox = defineToggleGroup(resourceTypes);

        HBox filePane = defineFilePane();

        HBox buttonsPane = defineButtonsPane();

        mainView.getChildren().addAll(title, toggleGroupBox, filePane, buttonsPane);

        rootPane.setCenter(mainView);
    }

    private HBox defineButtonsPane() {
        HBox buttonsPane = new HBox(10);
        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(actionEvent -> new KeysView(primaryStage, rootPane, keyData).initialize());

        Button saveButton = new Button("Save");
        saveButton.setOnAction(actionEvent -> saveFile());
        saveButton.disableProperty().bind(fileTypeToggleGroupValue.valueProperty().isNull().or(fileNameSelectedProperty.not()));

        buttonsPane.getChildren().addAll(cancelButton, saveButton);
        return buttonsPane;
    }

    private HBox defineFilePane() {
        HBox filePane = new HBox(10);
        filePane.setPadding(new Insets(20, 0, 20, 0));
        Label fileLabel = new Label();
        fileLabel.setText("Save to :");

        Label fileName = new Label();

        fileNameProperty = new SimpleStringProperty("...");
        fileNameSelectedProperty = new SimpleBooleanProperty(false);

        fileName.textProperty().bind(fileNameProperty);

        Button selectButton = new Button("Select", ScreenArtifacts.keysIconView);
        selectButton.setOnAction(actionEvent -> selectFile());

        filePane.getChildren().addAll(fileLabel, fileName, selectButton);
        return filePane;
    }

    private VBox defineToggleGroup(List<KeyResourceType> resourceTypes) {
        VBox toggleGroupBox = new VBox();
        toggleGroupBox.setPadding(new Insets(20, 0, 0, 0));

        // Group
        ToggleGroup group = new ToggleGroup();

        //
        RadioButton button1 = new RadioButton("JWK");
        button1.setToggleGroup(group);
        if (!resourceTypes.contains(KeyResourceType.JWK)) {
            button1.setDisable(true);
        }

        //
        RadioButton button2 = new RadioButton("JWKSet");
        button2.setToggleGroup(group);
        if (!resourceTypes.contains(KeyResourceType.JWKSET)) {
            button2.setDisable(true);
        }

        //
        RadioButton button3 = new RadioButton("PEM (supported in the future)");
        button3.setToggleGroup(group);
        button3.setDisable(true);

        //
        RadioButton button4 = new RadioButton("KeyStore  (supported in the future)");
        button4.setToggleGroup(group);
        button4.setDisable(true);

        fileTypeToggleGroupValue = new ToggleGroupValue();
        fileTypeToggleGroupValue.add(button1, KeyResourceType.JWK);
        fileTypeToggleGroupValue.add(button2, KeyResourceType.JWKSET);
        fileTypeToggleGroupValue.add(button3, KeyResourceType.PEM);
        fileTypeToggleGroupValue.add(button4, KeyResourceType.KEYSTORE);

        toggleGroupBox.getChildren().addAll(button1, button2, button3, button4);
        return toggleGroupBox;
    }

    private void saveFile() {
        KeyResourceType keyResourceType = (KeyResourceType) fileTypeToggleGroupValue.getValue();
        String fileName = defineFileName(keyResourceType, fileNameProperty.getValue());

        KeyWriter keyWriter = new KeyWriter();
        List<AtbashKey> selectedKeys = keyData.getSelectedKeys();
        for (AtbashKey selectedKey : selectedKeys) {

            keyWriter.writeKeyResource(selectedKey, keyResourceType, fileName, null, null);
        }

        // FIXME use InfoDialog
    }

    private String defineFileName(KeyResourceType keyResourceType, String fileName) {
        String result = fileName;
        boolean hasSuffix = false;
        for (String suffix : keyResourceType.getSuffixes()) {
            if (fileName.toLowerCase(Locale.ENGLISH).endsWith(suffix)) {
                hasSuffix = true;
            }
        }
        if (!hasSuffix) {
            result += keyResourceType.getSuffixes()[0];
        }
        return result;
    }

    private void selectFile() {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showSaveDialog(null);

        if (selectedFile != null) {
            try {
                fileNameProperty.setValue(selectedFile.getCanonicalPath());
                fileNameSelectedProperty.setValue(true);
            } catch (IOException e) {
                e.printStackTrace();
                // FIXME
            }

        }

    }

    // FIXME use this in the selectFile (maybe on the already selected type)
    private File askFileName() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save JWK File");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JWK result (*.jwk)", "*.jwk"));
        fileChooser.setInitialFileName("*.jwk");

        File result = fileChooser.showSaveDialog(primaryStage);
        if (result != null) {
            if (!result.getName().endsWith(".jwk")) {
                // FIXME
                throw new RuntimeException(result.getName() + " has no valid JWK-extension.");
            }
        }
        return result;
    }

}
