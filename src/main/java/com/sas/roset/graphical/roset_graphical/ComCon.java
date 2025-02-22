package com.sas.roset.graphical.roset_graphical;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;

/*
    +-----------------------------------------------------------------------+
    | ROSET Graphical (ROS Encryption Tool) -                               |
    | The official encryption tool providing access to the                  |
    | SAS-RCS/RBS Encryption Algorithms.                                    |
    |                                                                       |
    | Copyright (C) 2025-Present Saaiq Abdulla Saeed (saaiqSAS)             |
    |                                                                       |
    | This program is free software: you can redistribute it and/or modify  |
    | it under the terms of the GNU General Public License as published by  |
    | the Free Software Foundation, either version 3 of the License, or     |
    | (at your option) any later version.                                   |
    |                                                                       |
    | This program is distributed in the hope that it will be useful,       |
    | but WITHOUT ANY WARRANTY; without even the implied warranty of        |
    | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the          |
    | GNU General Public License for more details.                          |
    |                                                                       |
    | You should have received a copy of the GNU General Public License     |
    | along with this program. If not, see <https://www.gnu.org/licenses/>. |
    |                                                                       |
    | For support or to contact the author:                                 |
    | Email: sas.roset@gmail.com                                            |
    +-----------------------------------------------------------------------+
*/

public class ComCon {
    // Common Controller for non-main windows

    @FXML
    public VBox wel_root;
    @FXML
    public VBox log_root;
    @FXML
    public TextArea log_display;

    // Log Window
    @FXML
    protected void log_close_window_button_onAction() {
        Stage stage = (Stage) log_root.getScene().getWindow();
        MainApp.LOG_WIN_SHOWN = false;
        stage.hide();
    }

    // Welcome Window
    @FXML
    protected void wel_close_window_button_onAction() {
        Stage stage = (Stage) wel_root.getScene().getWindow();
        stage.close();
    }

    @FXML
    protected void wel_help_button_onAction() throws IOException {
        MainApp.goToHelp();
    }

    @FXML
    protected void wel_terms_button_onAction() throws IOException {
        MainApp.goToTerms();
    }

}
