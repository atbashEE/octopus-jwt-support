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

import be.atbash.ee.security.octopus.keys.subview.model.AtbashKeyItem;
import be.atbash.ee.security.octopus.keys.subview.model.KeyData;
import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.cell.CheckBoxTableCell;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.util.Optional;

import static be.atbash.ee.security.octopus.ScreenArtifacts.*;

/**
 *
 */

public class KeysView extends SubView {

    private final KeyData keyData;

    private TableView<AtbashKeyItem> tableView;
    private HBox buttonRow;

    public KeysView(Stage primaryStage, BorderPane rootPane, KeyData keyData) {
        super(primaryStage, rootPane);
        this.keyData = keyData;
    }

    @Override
    public void initialize() {
        defineTable();
        defineTableButtons();

        defineSubView();
    }

    private void defineTable() {
        tableView = new TableView<>();
        tableView.setEditable(true);  // For the selected column

        TableColumn<AtbashKeyItem, String> idCol = new TableColumn<>("ID");
        TableColumn<AtbashKeyItem, String> typeCol = new TableColumn<>("Type");
        TableColumn<AtbashKeyItem, Boolean> privateCol = new TableColumn<>("Private/Public");
        TableColumn<AtbashKeyItem, Boolean> selectedCol = new TableColumn<>("Selected");

        idCol.setCellValueFactory(new PropertyValueFactory<>("kid"));
        typeCol.setCellValueFactory(new PropertyValueFactory<>("keyType"));
        privateCol.setCellValueFactory(new PropertyValueFactory<>("asymmetricText"));
        selectedCol.setCellValueFactory(new PropertyValueFactory<>("selected"));

        selectedCol.setCellFactory(CheckBoxTableCell.forTableColumn(selectedCol));
        selectedCol.setEditable(true);

        tableView.getColumns().addAll(idCol, typeCol, privateCol, selectedCol);
        tableView.setItems(getItemList());

    }

    private void defineSubView() {
        VBox mainView = new VBox();
        mainView.setPadding(new Insets(10, 10, 10, 10));

        Text title = new Text("Cryptographic keys");
        title.setFont(viewTitleFont);

        mainView.getChildren().addAll(title, buttonRow, tableView);

        rootPane.setCenter(mainView);
    }

    private void defineTableButtons() {
        Button addButton = new Button("Add", addIconView);
        addButton.setOnAction(actionEvent -> new NewKeyView(primaryStage, rootPane, keyData).initialize());

        Button removeButton = new Button("Remove", removeIconView);
        removeButton.setOnAction(actionEvent -> onRemove(tableView));
        removeButton.disableProperty().bind(Bindings.isEmpty(tableView.getSelectionModel().getSelectedItems()));

        // FIXME Not active for the moment
        //Button importButton = new Button("Import", importIconView);
        //importButton.setOnAction(actionEvent -> onImport());

        buttonRow = new HBox(30);  // Buttons
        buttonRow.setPadding(new Insets(10, 10, 10, 10));
        buttonRow.getChildren().addAll(addButton, removeButton/*, importButton*/);

    }

    private void onRemove(TableView<AtbashKeyItem> table) {
        AtbashKeyItem atbashKeyItem = table.getSelectionModel().getSelectedItem();
        if (atbashKeyItem == null) {
            return;
        }
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirmation Dialog");
        alert.setHeaderText("Confirm delete");
        alert.setContentText(String.format("Are you sure you want to delete key with id '%s'?", atbashKeyItem.getKid()));

        Optional<ButtonType> result = alert.showAndWait();
        if (result.isPresent()) {
            if (ButtonType.OK.equals(result.get())) {
                keyData.removeKey(atbashKeyItem);

                //Wierd JavaFX bug
                table.setItems(null);
                table.layout();
                tableView.setItems(getItemList());
            }
        }
    }

    private void onImport() {
        File importFile = chooseFile();
        if (importFile != null) {
            new ImportJWKView(primaryStage, rootPane, keyData, importFile).initialize();
        }
    }

    private File chooseFile() {
        // FIXME Duplicate with ApplicationMenu onOpenFile
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Cryptographic  File");

        // FIXME Use the suffixed from KeyResourceType
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("JWK Files", "*.jwk")
                , new FileChooser.ExtensionFilter("JWK Set Files", "*.jwks")
        );

        return fileChooser.showOpenDialog(primaryStage);

    }

    private ObservableList<AtbashKeyItem> getItemList() {

        return FXCollections.observableArrayList(keyData.getItems());
    }

}
