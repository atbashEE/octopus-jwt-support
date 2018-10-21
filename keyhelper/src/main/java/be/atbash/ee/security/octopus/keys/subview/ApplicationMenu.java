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

import be.atbash.ee.security.octopus.keys.subview.model.KeyData;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SeparatorMenuItem;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;

/**
 *
 */

public class ApplicationMenu extends SubView {

    private KeyData keyData = new KeyData();

    public ApplicationMenu(Stage primaryStage, BorderPane rootPane) {
        super(primaryStage, rootPane);
    }

    public void initialize() {
        MenuBar menuBar = new MenuBar();
        // Make same width as the stage
        menuBar.prefWidthProperty().bind(primaryStage.widthProperty());
        rootPane.setTop(menuBar);

        // File menu - new, save, exit
        Menu fileMenu = new Menu("File");
        MenuItem newMenuItem = createMenuItem("New", actionEvent -> this.onNewFile());

        MenuItem openMenuItem = createMenuItem("Open", actionEvent -> this.onOpenFile());

        MenuItem saveMenuItem = createMenuItem("Save", actionEvent -> this.onSaveFile());
        saveMenuItem.disableProperty().bind(keyData.changedProperty().not());

        MenuItem exitMenuItem = createMenuItem("Exit", actionEvent -> Platform.exit());

        fileMenu.getItems().addAll(newMenuItem, openMenuItem, saveMenuItem,
                new SeparatorMenuItem(), exitMenuItem);

        menuBar.getMenus().addAll(fileMenu);
    }

    private MenuItem createMenuItem(String aNew, EventHandler<ActionEvent> actionEventEventHandler) {
        MenuItem newMenuItem = new MenuItem(aNew);
        newMenuItem.setOnAction(actionEventEventHandler);
        return newMenuItem;
    }

    private void onNewFile() {
        keyData.onNewFile();
        new KeysView(primaryStage, rootPane, keyData).initialize();
    }

    private void onOpenFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Cryptographic  File");

        // FIXME Use the suffixed from KeyResourceType
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("JWK Files", "*.jwk")
                , new FileChooser.ExtensionFilter("JWK Set Files", "*.jwks")
        );

        File selectedFile = fileChooser.showOpenDialog(primaryStage);
        if (selectedFile != null) {
            keyData.onOpenFile(selectedFile);
            new KeysView(primaryStage, rootPane, keyData).initialize();
        }

    }

    private void onSaveFile() {
        new SaveTypeView(primaryStage, rootPane, keyData).initialize();

    }

}


