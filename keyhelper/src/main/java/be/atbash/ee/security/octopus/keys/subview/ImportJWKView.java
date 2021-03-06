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

import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.subview.model.AtbashKeyItem;
import be.atbash.ee.security.octopus.keys.subview.model.KeyData;
import javafx.beans.binding.Bindings;
import javafx.beans.property.adapter.JavaBeanBooleanProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import java.io.File;

import static be.atbash.ee.security.octopus.ScreenArtifacts.viewTitleFont;

/**
 *
 */

public class ImportJWKView extends SubView {

    private final KeyData keyData;
    private final KeyData importKeyData;

    private HBox buttonRow;

    private TableView<AtbashKeyItem> tableView;

    private JavaBeanBooleanProperty importPublicEnabledProperty;
    private JavaBeanBooleanProperty importEnabledProperty;

    public ImportJWKView(Stage primaryStage, BorderPane rootPane, KeyData keyData, File importFile) {
        super(primaryStage, rootPane);
        this.keyData = keyData;
        importKeyData = new KeyData();
        importKeyData.onOpenFile(importFile);
    }

    @Override
    public void initialize() {
        defineTable();
        defineTableButtons();

        defineSubView();
    }

    private void defineTable() {
        tableView = new TableView<>();

        TableColumn<AtbashKeyItem, String> idCol = new TableColumn<>("ID");
        TableColumn<AtbashKeyItem, String> typeCol = new TableColumn<>("Type");
        TableColumn<AtbashKeyItem, Boolean> privateCol = new TableColumn<>("Private");
        TableColumn<AtbashKeyItem, String> keyUseCol = new TableColumn<>("Key Usage");

        idCol.setCellValueFactory(new PropertyValueFactory<>("kid"));
        typeCol.setCellValueFactory(new PropertyValueFactory<>("keyType"));
        privateCol.setCellValueFactory(new PropertyValueFactory<>("privatePart"));
        keyUseCol.setCellValueFactory(new PropertyValueFactory<>("keyUse"));

        tableView.getColumns().addAll(idCol, typeCol, privateCol, keyUseCol);
        ObservableList<AtbashKeyItem> list = getItemList();
        tableView.setItems(list);

        /*
        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                System.out.println(newSelection);
            }
        });
        */

    }

    private void defineTableButtons() {
        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(actionEvent -> new KeysView(primaryStage, rootPane, keyData).initialize());

        Button importPublicButton = new Button("Import public");
        importPublicButton.setOnAction(actionEvent -> importPublicKey());

        importPublicButton.disableProperty().bind(Bindings.createBooleanBinding(this::isImportPublicButtonDisabled, tableView.getSelectionModel().getSelectedItems()));

        Button importButton = new Button("Import");
        importButton.setOnAction(actionEvent -> importKey());
        importButton.disableProperty().bind(Bindings.isEmpty(tableView.getSelectionModel().getSelectedItems()));

        buttonRow = new HBox(30);  // Buttons
        buttonRow.setPadding(new Insets(10, 10, 10, 10));
        buttonRow.getChildren().addAll(cancelButton, importPublicButton, importButton);

    }

    private void importPublicKey() {
        /*
        AtbashKeyItem item = tableView.getSelectionModel().getSelectedItem();
        keyData.add(importKeyData.getKey(item.getKid()).toPublicJWK());
        new KeysView(primaryStage, rootPane, keyData).initialize();
        new InfoDialog("Public key imported").showDialog();
        */
    }

    private void importKey() {
        /*
        AtbashKeyItem item = tableView.getSelectionModel().getSelectedItem();
        keyData.add(importKeyData.getKey(item.getKid()));
        new KeysView(primaryStage, rootPane, keyData).initialize();
        new InfoDialog("Key imported").showDialog();
        */
    }

    private Boolean isImportPublicButtonDisabled() {
        AtbashKeyItem atbashKeyItem = tableView.getSelectionModel().getSelectedItem();
        return atbashKeyItem == null || !(atbashKeyItem.getAsymmetricPart().equals(AsymmetricPart.PRIVATE));
    }

    private void defineSubView() {
        VBox mainView = new VBox();
        mainView.setPadding(new Insets(10, 10, 10, 10));

        Text title = new Text("Import JWK");
        title.setFont(viewTitleFont);

        mainView.getChildren().addAll(title, tableView, buttonRow);

        rootPane.setCenter(mainView);
    }

    private ObservableList<AtbashKeyItem> getItemList() {

        return FXCollections.observableArrayList(importKeyData.getItems());
    }

}
