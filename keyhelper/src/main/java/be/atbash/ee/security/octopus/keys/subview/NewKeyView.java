/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.ECGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.GenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.keys.subview.model.KeyData;
import be.atbash.ee.security.octopus.nimbus.jwk.Curve;
import be.atbash.util.exception.AtbashUnexpectedException;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

/**
 *
 */

public class NewKeyView extends SubView {

    private final KeyData keyData;

    private StringProperty id = new SimpleStringProperty();
    private StringProperty keyType = new SimpleStringProperty();
    private StringProperty keySize = new SimpleStringProperty();
    private StringProperty curveName = new SimpleStringProperty();
    private BooleanProperty keySizeDisabled = new SimpleBooleanProperty();
    private BooleanProperty curveNameDisabled = new SimpleBooleanProperty();

    protected NewKeyView(Stage primaryStage, BorderPane rootPane, KeyData keyData) {
        super(primaryStage, rootPane);
        this.keyData = keyData;
    }

    @Override
    public void initialize() {
        GridPane grid = new GridPane();
        grid.setAlignment(Pos.CENTER);
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(25, 25, 25, 25));

        Label kidLabel = new Label("Id :");
        grid.add(kidLabel, 0, 0);

        HBox idPane = new HBox(10);
        TextField kidField = new TextField();
        kidField.setPrefColumnCount(20);
        kidField.textProperty().bindBidirectional(id);

        Button kidButton = new Button("id");
        kidButton.setOnAction(eventAction -> id.setValue(UUID.randomUUID().toString()));

        idPane.getChildren().addAll(kidField, kidButton);
        grid.add(idPane, 1, 0);

        Label typeLabel = new Label("Type :");
        grid.add(typeLabel, 0, 1);

        ComboBox keyTypeComboBox = new ComboBox();
        keyTypeComboBox.getItems().addAll(
                "RSA", "EC"
        );
        keyTypeComboBox.valueProperty().bindBidirectional(keyType);
        grid.add(keyTypeComboBox, 1, 1);

        keyTypeComboBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            curveNameDisabled.set(true);
            keySizeDisabled.set(true);
            if ("RSA".equals(newValue)) {
                keySizeDisabled.set(false);
            }
            if ("EC".equals(newValue)) {
                curveNameDisabled.set(false);
            }
        });

        Label curveLabel = new Label("Curve name :");
        grid.add(curveLabel, 0, 2);

        ComboBox curveComboBox = new ComboBox();
        curveComboBox.getItems().addAll(
                "P-256", "P-256K", "P-384", "P-521"
        );
        curveComboBox.valueProperty().bindBidirectional(curveName);
        curveNameDisabled.set(true);
        curveComboBox.disableProperty().bind(curveNameDisabled);
        grid.add(curveComboBox, 1, 2);

        Label lengthLabel = new Label("Length :");
        grid.add(lengthLabel, 0, 3);

        ComboBox keyLengthComboBox = new ComboBox();
        keyLengthComboBox.getItems().addAll(
                "2048",
                "3072",
                "4096"
        );
        keyLengthComboBox.valueProperty().bindBidirectional(keySize);

        keySizeDisabled.set(true);
        keyLengthComboBox.disableProperty().bind(keySizeDisabled);
        grid.add(keyLengthComboBox, 1, 3);

        HBox buttonPane = new HBox(10);
        Button saveButton = new Button("Apply");
        saveButton.setOnAction(actionEvent -> this.createKey());

        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(actionEvent -> new KeysView(primaryStage, rootPane, keyData).initialize());

        buttonPane.getChildren().addAll(cancelButton, saveButton);

        grid.add(buttonPane, 1, 4);

        rootPane.setCenter(grid);
    }

    private void createKey() {
        GenerationParameters parameters = null;
        if ("RSA".equals(keyType.get())) {
            parameters = createRSAParameters();
        }
        if ("EC".equals(keyType.get())) {
            parameters = createECParameters();
        }

        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(parameters);
        keyData.add(keys);

        new KeysView(primaryStage, rootPane, keyData).initialize();
    }

    private RSAGenerationParameters createRSAParameters() {
        return new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(id.getValue())
                .withKeySize(Integer.parseInt(keySize.getValue()))
                .build();
    }

    private ECGenerationParameters createECParameters() {
        return new ECGenerationParameters.ECGenerationParametersBuilder()
                .withKeyId(id.getValue())
                .withCurveName(Curve.parse(curveName.get()).getStdName())
                .build();
    }

    private RSAPublicKey getPublicKey(List<AtbashKey> keys) {
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        if (publicKeys.size() != 1) {
            throw new AtbashUnexpectedException("We should always find a Public RSA key");
        }
        return (RSAPublicKey) publicKeys.get(0).getKey();
    }

    private RSAPrivateKey getPrivateKey(List<AtbashKey> keys) {
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        if (publicKeys.size() != 1) {
            throw new AtbashUnexpectedException("We should always find a private RSA key");
        }
        return (RSAPrivateKey) publicKeys.get(0).getKey();
    }
}
