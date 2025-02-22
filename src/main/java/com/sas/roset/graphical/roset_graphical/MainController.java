package com.sas.roset.graphical.roset_graphical;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.ImageView;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.MouseButton;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.converter.IntegerStringConverter;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;

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

public class MainController implements Initializable {

    protected static boolean GENERATE_KEY = true;
    protected static byte FUNCTION_TYPE = 0; // 0:encrypt  1:decrypt
    protected static byte INPUT_TYPE = 0; // 0:text  1:file
    protected static byte ALGORITHM_TO_USE = 0; // 0:SAS-RCS  1:SAS-RBS

    //key gen
    protected static boolean GK_KEY_LENGTH_IS_BITWISE = true;
    protected static byte GK_RGM_STATUS = 1; // 0:disabled   1:partial   2:full
    protected static byte GK_RGM_BASE = 2; // 0:s2   1:s16   2:s64
    protected static boolean GK_RANDOM_CHAR_SELECTION = false;
    protected static boolean GK_SAVE_KEY_TO_KEYSTORE = false;
    protected static boolean INVALID_KEY_PROTECTION = false;
    protected static boolean QUICK_PROCESSING = false;
    protected static boolean RANDOM_FILE_NAMES = false;

    // Additional
    private static boolean ERR_KEY_GEN_INPUT_FIELDS = false;
    protected static HashMap<String,DataFileInput_File> FILES_TO_PROCESS = new HashMap<>();
    private static String ID_OF_SELECTED_DATA_FILE = "";
    private static File LAST_VISITED_DIR;
    
    protected static String OUTPUT_DIR;
    protected static String COMMON_PATH;

    private static boolean RBS_BUTTON_DISABLED = false;
    private static boolean RCS_BUTTON_DISABLED = false;
    private static boolean RBS_UNSUPPORTED = false;

    private static boolean NEXT_BUTTON_DISABLED = false;
    private static boolean PROCESS_BUTTON_DISABLED = false;
    protected static File KEY_SAVE_FILE;

    // UI components
    public VBox root;
    public Button keys_tab;
    public Button data_tab;
    public GridPane keys_tab_display;
    public Button function_encrypt_button;
    public Button function_decrypt_button;
    public TextField select_key_path;
    public Button gk_key_length_bitwise_rb;
    public Button gk_key_length_custom_rb;
    //public Button RGM_status_disabled_rb;
    public Button RGM_status_partial_rb;
    public Button RGM_status_full_rb;
    public Button RGM_base_s2_rb;
    public Button RGM_base_s16_rb;
    public Button RGM_base_s64_rb;
    public TextField data_size_for_every_input;
    public TextField data_size_add_input;
    public Button rand_char_selection_checkbox;
    public TextField save_key_file_name_input;
    public Button save_to_keystore_checkbox;
    public Button main_next_button;
    private static Button  main_next_button_STATIC;
    public VBox generate_key_box;
    public VBox select_key_box;
    public GridPane data_tab_display;
    public TextField num_of_st_key_input;
    public Button algo_rcs;
    public Button algo_rbs;
    public Button input_type_text;
    public Button input_type_file;
    public VBox input_text_box;
    public VBox input_file_box;
    public TextArea input_text_input_field;
    public VBox output_text_box;
    public VBox output_file_box;
    public TextArea output_text_output_field;
    public TableView<KeyStore_Key> keystore_table;
    public TableColumn<KeyStore_Key,String> keystore_table_key_name;
    public TableColumn<KeyStore_Key,String> keystore_table_key_length;
    public TableColumn<KeyStore_Key,String> keystore_table_st_keys;
    public TextField gk_key_length_bitwise_input;
    public TextField gk_key_length_custom_input;
    public Text msg_text;
    protected static Text msg_text_STATIC;
    public Button main_process_button;
    private static Button main_process_button_STATIC;
    public Text num_of_rev_st_key;
    public TextField output_directory_file_input;
    public TextField proc_sett_threads_input;
    public Button invalid_key_protection_checkbox;
    public Button quick_processing_checkbox;
    public TableView<DataFileInput_File> input_file_table;
    public TableColumn<KeyStore_Key,String> input_file_table_name;
    public TableColumn<KeyStore_Key,String> input_file_table_type;
    public HBox select_key_header_background;
    public HBox generate_key_header_background;
    public ImageView key_extracted_icon;
    public ImageView quick_processing_icon;
    public Button random_file_names_checkbox;
    public Text version;
    public Button key_generate_button;
    public Button key_select_button;
    public Button RGM_base_s10_rb;
    public Button algo_icon;
    public Button input_file_remove_button;
    public TextField proc_sett_threads_per_file_input;

    // init interface
    public void initialize(URL location, ResourceBundle resources) {
        // --- Basic UI Setup ---
        //generate_key_box is selected in fxml
        keys_tab_onAction();
        function_encrypt_button_onAction();
        gk_key_length_bitwise_rb_onAction();
        RGM_status_partial_rb_onAction();
        RGM_base_s64_rb_onAction();
        input_type_file_button_onAction();
        algo_rcs_button_onAction();
        save_to_keystore_checkbox_onAction();
        random_file_names_checkbox_onAction();
        quick_processing_checkbox_onAction();
        input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("disabled_button");


        Platform.runLater(() -> {
            // --- Text Fields to Int only ---
            TextFormatter<Integer> textFormatter_Int_1 = new TextFormatter<>(new IntegerStringConverter(), 8);  // key length bits
            TextFormatter<Integer> textFormatter_Int_2 = new TextFormatter<>(new IntegerStringConverter(), 256);// key length custom
            TextFormatter<Integer> textFormatter_Int_3 = new TextFormatter<>(new IntegerStringConverter(), 3);  // for every
            TextFormatter<Integer> textFormatter_Int_4 = new TextFormatter<>(new IntegerStringConverter(), 2);  // add
            TextFormatter<Integer> textFormatter_Int_5 = new TextFormatter<>(new IntegerStringConverter(), 3);  // num of Static keys
            TextFormatter<Integer> textFormatter_Int_6 = new TextFormatter<>(new IntegerStringConverter(), 4);  // max threads
            TextFormatter<Integer> textFormatter_Int_7 = new TextFormatter<>(new IntegerStringConverter(), 4);  // max threads per file
            gk_key_length_bitwise_input.setTextFormatter(textFormatter_Int_1);
            gk_key_length_custom_input.setTextFormatter(textFormatter_Int_2);
            data_size_for_every_input.setTextFormatter(textFormatter_Int_3);
            data_size_add_input.setTextFormatter(textFormatter_Int_4);
            num_of_st_key_input.setTextFormatter(textFormatter_Int_5);
            proc_sett_threads_input.setTextFormatter(textFormatter_Int_6);
            proc_sett_threads_per_file_input.setTextFormatter(textFormatter_Int_7);


            // --- Text Fields Focus Listeners ---

            gk_key_length_bitwise_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    gk_key_length_bitwise_input.getStyleClass().clear();
                    gk_key_length_bitwise_input.getStyleClass().add("input-field");
                    clearLogCondition("Bitwise key length should be between 7 to 20");
                    ERR_KEY_GEN_INPUT_FIELDS = false;
                } else {
                    if (GK_KEY_LENGTH_IS_BITWISE) {
                        int input = SAS_ROSET.stringToInt(gk_key_length_bitwise_input.getText());
                        if (input < 7 || input > 20) {
                            log("Bitwise key length should be between 7 to 20", true);
                            ERR_KEY_GEN_INPUT_FIELDS = true;
                            gk_key_length_bitwise_input.getStyleClass().clear();
                            gk_key_length_bitwise_input.getStyleClass().add("input-field-error");
                        } else {
                            gk_key_length_custom_input.setText("" + SAS_ROSET.keyLengthForBits(input));
                        }
                    }
                }
            });

            gk_key_length_custom_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    gk_key_length_custom_input.getStyleClass().clear();
                    gk_key_length_custom_input.getStyleClass().add("input-field");
                    clearLogCondition("Custom key length should be between 100 to 1050000");
                    ERR_KEY_GEN_INPUT_FIELDS = false;
                } else {
                    if (!GK_KEY_LENGTH_IS_BITWISE) {
                        int input = SAS_ROSET.stringToInt(gk_key_length_custom_input.getText());
                        if (input < 100 || input > 1050000) {
                            log("Custom key length should be between 100 to 1050000", true);
                            ERR_KEY_GEN_INPUT_FIELDS = true;
                            gk_key_length_custom_input.getStyleClass().clear();
                            gk_key_length_custom_input.getStyleClass().add("input-field-error");
                        }
                    }
                }
            });

            data_size_for_every_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    data_size_for_every_input.getStyleClass().clear();
                    data_size_for_every_input.getStyleClass().add("input-field");
                    clearLogCondition("Data increase 'for every' should be between 0 to 9");
                    ERR_KEY_GEN_INPUT_FIELDS = false;
                } else {
                    int input = SAS_ROSET.stringToInt(data_size_for_every_input.getText());
                    if (input < 0 || input > 9) {
                        log("Data increase 'for every' should be between 0 to 9", true);
                        ERR_KEY_GEN_INPUT_FIELDS = true;
                        data_size_for_every_input.getStyleClass().clear();
                        data_size_for_every_input.getStyleClass().add("input-field-error");
                    }
                }
            });

            data_size_add_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    data_size_add_input.getStyleClass().clear();
                    data_size_add_input.getStyleClass().add("input-field");
                    clearLogCondition("Data increase 'add' should be between 0 to 99");
                    ERR_KEY_GEN_INPUT_FIELDS = false;
                } else {
                    int input = SAS_ROSET.stringToInt(data_size_add_input.getText());
                    if (input < 0 || input > 99) {
                        log("Data increase 'add' should be between 0 to 99", true);
                        ERR_KEY_GEN_INPUT_FIELDS = true;
                        data_size_add_input.getStyleClass().clear();
                        data_size_add_input.getStyleClass().add("input-field-error");
                    }
                }
            });

            num_of_st_key_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    num_of_st_key_input.getStyleClass().clear();
                    num_of_st_key_input.getStyleClass().add("input-field");
                    clearLogCondition("Number of static keys should be between 1 and 100");
                    ERR_KEY_GEN_INPUT_FIELDS = false;
                } else {
                    int input = SAS_ROSET.stringToInt(num_of_st_key_input.getText());
                    if (input <= 0 || input > 100) {
                        log("Number of static keys should be between 1 to 100", true);
                        ERR_KEY_GEN_INPUT_FIELDS = true;
                        num_of_st_key_input.getStyleClass().clear();
                        num_of_st_key_input.getStyleClass().add("input-field-error");
                    } else {
                        num_of_rev_st_key.setText("+ " + (input / 2));
                    }
                }
            });

            save_key_file_name_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    save_key_file_name_input.getStyleClass().clear();
                    save_key_file_name_input.getStyleClass().add("input-field");
                    clearLogCondition("Please enter a name for the key file");
                }
            });

            proc_sett_threads_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    proc_sett_threads_input.getStyleClass().clear();
                    proc_sett_threads_input.getStyleClass().add("input-field");
                    clearLogCondition("Maximum parallel files to process should be between 1 and 25");
                } else {
                    int input = SAS_ROSET.stringToInt(proc_sett_threads_input.getText());
                    if (input <= 0) {
                        proc_sett_threads_input.setText("4");
                    } else if (input > 25) {
                        log("Maximum parallel files to process should be between 1 and 25", true);
                        proc_sett_threads_input.getStyleClass().clear();
                        proc_sett_threads_input.getStyleClass().add("input-field-error");
                    }
                }
            });

            proc_sett_threads_per_file_input.focusedProperty().addListener((arg0, oldPropertyValue, newPropertyValue) -> {
                if (newPropertyValue) {
                    proc_sett_threads_per_file_input.getStyleClass().clear();
                    proc_sett_threads_per_file_input.getStyleClass().add("input-field");
                    clearLogCondition("Maximum threads per file should be between 1 and 50");
                } else {
                    int input = SAS_ROSET.stringToInt(proc_sett_threads_per_file_input.getText());
                    if (input <= 0) {
                        proc_sett_threads_per_file_input.setText("4");
                    } else if (input > 50) {
                        log("Maximum threads per file should be between 1 and 50", true);
                        proc_sett_threads_per_file_input.getStyleClass().clear();
                        proc_sett_threads_per_file_input.getStyleClass().add("input-field-error");
                    }
                }
            });


            // --- Un Movable table columns setup ---
            keystore_table_key_name.setReorderable(false);
            keystore_table_key_length.setReorderable(false);
            keystore_table_st_keys.setReorderable(false);
            input_file_table_name.setReorderable(false);
            input_file_table_type.setReorderable(false);


            // --- Keystore table setup ---
            keystore_table_key_name.setCellValueFactory(new PropertyValueFactory<>("name"));
            keystore_table_key_length.setCellValueFactory(new PropertyValueFactory<>("length"));
            keystore_table_st_keys.setCellValueFactory(new PropertyValueFactory<>("st_keys"));

            keystore_table.setRowFactory(tv -> {
                TableRow<KeyStore_Key> row = new TableRow<>();
                row.setOnMouseClicked(event -> {
                    if (!row.isEmpty() && event.getButton() == MouseButton.PRIMARY) {
                        KeyStore_Key rowData = row.getItem();
                        select_key_path.setText(rowData.getPath()); // set data to field
                    }
                });
                return row;
            });

            extract_keyStore_data();

            // --- Data File Input table setup ---
            input_file_table_type.setCellValueFactory(new PropertyValueFactory<>("type"));
            input_file_table_name.setCellValueFactory(new PropertyValueFactory<>("name"));

            input_file_table.setRowFactory(tv -> {
                TableRow<DataFileInput_File> row = new TableRow<>();
                row.setOnMouseClicked(event -> {
                    if (!row.isEmpty() && event.getButton() == MouseButton.PRIMARY) {
                        DataFileInput_File rowData = row.getItem();
                        ID_OF_SELECTED_DATA_FILE = rowData.getID();
                        input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("white_button");
                    }
                });
                return row;
            });

            // --- Variable Initialization ---
            msg_text_STATIC = msg_text;
            main_next_button_STATIC = main_next_button;
            main_process_button_STATIC = main_process_button;

            log("Developed by saaiqSAS, Licensed under GNU GPLv3", false);
            version.setText(MainApp.VERSION);
        });
    }

    private void extract_keyStore_data() {
        new Thread( () -> {

            ObservableList<KeyStore_Key> keystore_keys = FXCollections.observableArrayList();

            File keyStore_Dir = new File("roset_keystore");

            if (!keyStore_Dir.exists()) {
                MainApp.firstTime = true;
                keyStore_Dir.mkdirs();
            }

            File[] keys = keyStore_Dir.listFiles();

            if (keys != null) {
                for (File eFile: keys) {
                    try {
                        //Check key file
                        FileInputStream fileInputStream = new FileInputStream(eFile);
                        // Read bytes until newline character is encountered
                        ByteArrayOutputStream metaBytes = new ByteArrayOutputStream();
                        int currentByte;
                        while ((currentByte = fileInputStream.read()) != '\n') {
                            metaBytes.write(currentByte);
                        }

                        // Get Metadata
                        String file_name = metaBytes.toString(StandardCharsets.UTF_8);
                        int kLength = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                        int st_keys = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                        int version = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));

                        if (file_name != null && eFile.getName().toLowerCase().endsWith(".rosk")) {
                            if ( (fileInputStream.readAllBytes().length-40)/(4*kLength) == st_keys+1) { // count keys
                                keystore_keys.add(new KeyStore_Key(file_name, kLength, st_keys, eFile.getAbsolutePath()));
                            }
                        }

                        metaBytes.close();
                        fileInputStream.close();
                    } catch (Exception e) {
                        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] Could not extract keystore data:\n"+e+"\n"));
                    }
                    keystore_table.setItems(keystore_keys);
                }
            }

        }).start();
    }

    // main window close button
    @FXML
    protected void main_close_window_button_onAction() {
        Stage stage = (Stage) root.getScene().getWindow();
        SAS_ROSET.stopAllProcesses();
        stage.close();
        Platform.exit();
        System.exit(0);
    }

    // main window minimize button
    @FXML
    protected void main_minimize_window_button_onAction() {
        Stage stage = (Stage) root.getScene().getWindow();
        stage.setIconified(true);
    }

    // log window open
    @FXML
    protected void log_display_button_onAction() {
        MainApp.showLogWin();
    }

    // help
    @FXML
    protected void help_button_onAction() throws IOException {
        MainApp.goToHelp();
    }



    // keys_tab
    @FXML
    protected void keys_tab_onAction() {
        keys_tab.getStyleClass().clear(); keys_tab.getStyleClass().add("main_tabs_active");
        data_tab.getStyleClass().clear(); data_tab.getStyleClass().add("main_tabs");
        data_tab_display.setVisible(false);
        keys_tab_display.setVisible(true);
        main_process_button.setVisible(false);
        main_next_button.setVisible(true);
    }

    // data_tab
    @FXML
    protected void data_tab_onAction() {
        data_tab.getStyleClass().clear(); data_tab.getStyleClass().add("main_tabs_active");
        keys_tab.getStyleClass().clear(); keys_tab.getStyleClass().add("main_tabs");
        keys_tab_display.setVisible(false);
        data_tab_display.setVisible(true);
        main_next_button.setVisible(false);
        main_process_button.setVisible(true);
    }



    // main next button
    @FXML
    protected void main_next_button_onAction() {
        try {
            if (NEXT_BUTTON_DISABLED) {
                return;
            }

            if (GENERATE_KEY && !GK_SAVE_KEY_TO_KEYSTORE) {
                if (save_key_file_name_input.getText().isEmpty()) {
                    log("Please enter a name for the key file", true);
                    save_key_file_name_input.getStyleClass().clear();
                    save_key_file_name_input.getStyleClass().add("input-field-error");
                    return;
                }
                String save_key_file_name = save_key_file_name_input.getText();

                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Save Key");
                fileChooser.setInitialFileName(save_key_file_name + ".rosk");
                FileChooser.ExtensionFilter extensionFilter = new FileChooser.ExtensionFilter("ROSK File (*.rosk)", "*.rosk");
                fileChooser.getExtensionFilters().add(extensionFilter);

                Stage stage = (Stage) root.getScene().getWindow();
                KEY_SAVE_FILE = fileChooser.showSaveDialog(stage);

            }

            new Thread(() -> {
                SAS_ROSET.resetAllKeyStores();
                quick_processing_icon.setVisible(false);
                key_extracted_icon.setVisible(false);

                if (GENERATE_KEY) { // Generate Key
                    generateKey();
                } else { // Select Key
                    selectKey();
                }
            }).start();
        } catch (Exception e) {
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] An unexpected error has occurred after clicking 'Next' button:\n"+ e + "\n"));
        }
    }
    
    protected static void enable_next_process_button() {
        main_next_button_STATIC.getStyleClass().clear();  main_next_button_STATIC.getStyleClass().add("blue_button");
        PROCESS_BUTTON_DISABLED = false;
        
        main_process_button_STATIC.getStyleClass().clear(); main_process_button_STATIC.getStyleClass().add("blue_button");
        NEXT_BUTTON_DISABLED = false;
        
    }
    
    private void disable_next_process_button() {
        main_next_button.getStyleClass().clear(); main_next_button.getStyleClass().add("disabled_button");
        PROCESS_BUTTON_DISABLED = true;

        main_process_button.getStyleClass().clear(); main_process_button.getStyleClass().add("disabled_button");
        NEXT_BUTTON_DISABLED = true;
    }

    private void generateKey() {
        // --- Checking UI inputs ---
        if (ERR_KEY_GEN_INPUT_FIELDS) {return;}

        int key_length;
        if (GK_KEY_LENGTH_IS_BITWISE) {
            if (gk_key_length_bitwise_input.getText().isEmpty()) { log("Bitwise key length is empty",true); return;}
            key_length = SAS_ROSET.keyLengthForBits(SAS_ROSET.stringToInt(gk_key_length_bitwise_input.getText()));
        } else {
            if (gk_key_length_custom_input.getText().isEmpty()) { log("Custom key length is empty",true); return;}
            key_length = SAS_ROSET.stringToInt(gk_key_length_custom_input.getText());
        }

        if (data_size_for_every_input.getText().isEmpty()) { log("Data size increase 'for every' is empty",true); return;}
        int data_inc_for_every = SAS_ROSET.stringToInt(data_size_for_every_input.getText());

        if (data_size_add_input.getText().isEmpty()) { log("Data size increase 'add' is empty",true); return;}
        int data_inc_add = SAS_ROSET.stringToInt(data_size_add_input.getText());

        if (num_of_st_key_input.getText().isEmpty()) { log("Number of Static Keys is empty",true); return;}
        int num_of_st_keys = SAS_ROSET.stringToInt(num_of_st_key_input.getText());

        if (save_key_file_name_input.getText().isEmpty()) {
            log("Please enter a name for the key file",true);
            save_key_file_name_input.getStyleClass().clear(); save_key_file_name_input.getStyleClass().add("input-field-error");
            return;
        }
        String save_key_file_name = save_key_file_name_input.getText();

        clearLog();

        // --- Key Generation ---
        if (GK_SAVE_KEY_TO_KEYSTORE) {
            KEY_SAVE_FILE = new File(System.getProperty("user.dir") + "/roset_keystore/" + save_key_file_name + ".rosk");
        }
            
        if (KEY_SAVE_FILE != null) {
            if (KEY_SAVE_FILE.exists()) {log("Key file already exists",true); return;}
            log("Generating key file...",false);
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[*] Generating key file...\n"));
            disable_next_process_button();
            long startTime = System.currentTimeMillis();
            boolean keyFileGenerated = MainApp.generateKeyFile(key_length, data_inc_for_every, data_inc_add, num_of_st_keys);
            long endTime = System.currentTimeMillis();

            if (keyFileGenerated) {
                double duration = (double) (endTime - startTime) / 1000.0;
                log("Key file generated (in "+duration+"s)", false);
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Key file generated (in "+duration+"s)\n"));
                key_extracted_icon.setVisible(true);
                extract_keyStore_data();

                RBS_UNSUPPORTED = !SAS_ROSET.keyLengthSupportsRBS(key_length);
                enable_dissable_algos();

                data_tab_onAction();
               enable_next_process_button();

            } else {
                log("Could not generate key file",true);

            }
        }
    }

    private void selectKey() {
        String key_file_path = select_key_path.getText();
        if (key_file_path.isEmpty()) {
            log("A Key have not been selected",true);
            return;
        }
        File key_file = new File(key_file_path);

        if (key_file.exists()) {
            try {
                log("Extracting key from file...",false);
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[*] Extracting key from file...\n"));
                 disable_next_process_button();
                long startTime = System.currentTimeMillis();

                //Check key file
                FileInputStream fileInputStream = new FileInputStream(key_file);
                // Read bytes until newline character is encountered
                ByteArrayOutputStream metaBytes = new ByteArrayOutputStream();
                int currentByte;
                while ((currentByte = fileInputStream.read()) != '\n') {
                    metaBytes.write(currentByte);
                }

                // Get Metadata
                String file_name = metaBytes.toString(StandardCharsets.UTF_8);
                int kLength = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                int st_keys = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                int version = MainApp.byteArrayToInt(fileInputStream.readNBytes(4)); // version of ROSET used to generate key file

                if (version != MainApp.VERSION_IDENTIFIER) {
                    log("This key file '"+key_file.getName()+"' is supported by the ROSET version 'v"+version+".x.x'", true);
                    enable_next_process_button();
                    return;
                }

                if (file_name != null && key_file.getName().toLowerCase().endsWith(".rosk")) {
                    //String[] broken_line1 = SAS_ROSET.stringBreaker(line, ' ', false); // 0: name | 1: length | 2: num of st_keys

                    int[] dyn_key_read = MainApp.byteArrayToIntArray(fileInputStream.readNBytes(4*(kLength+10)));

                    // Check if current ROSET Algorithm version supports key version
                    if (!SAS_ROSET.apiSupportsVesrion((char) dyn_key_read[9])) {
                        log("This key is supported by the API version '"+SAS_ROSET.getApiVersionForId((char) dyn_key_read[9])+"'", true);
                        enable_next_process_button();
                        return;
                    }

                    int[][] st_keys_read = new int[st_keys][kLength];
                    for(int i = 0; i < st_keys; i++) {
                        st_keys_read[i] = MainApp.byteArrayToIntArray(fileInputStream.readNBytes(kLength*4));
                    }

                    //if (st_keys_read.length == st_keys) {
                        if (MainApp.extractKeys(dyn_key_read, st_keys_read)) {
                            double duration = (double) (System.currentTimeMillis() - startTime) /1000.0;
                            log("Key extracted (in "+duration+"s)", false);
                            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Key extracted (in "+duration+"s)\n"));
                            key_extracted_icon.setVisible(true);

                            RBS_UNSUPPORTED = !SAS_ROSET.keyLengthSupportsRBS(st_keys_read[0].length);
                            enable_dissable_algos();

                            data_tab_onAction();
                        } else {  log("Failed to extract key onto memory",true);}
                    //} else {  log("Invalid key file",true); return;}
                }
            } catch (Exception e) {
                log("An unexpected error has occurred while reading key file",true);
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] An unexpected error has occurred while reading key file:\n"+ e + "\n"));
            }

        } else {log("Could not find key file",true);}
       enable_next_process_button();
    }



    // main process button
    @FXML
    protected void main_process_button_onAction() {
        try {
            if (PROCESS_BUTTON_DISABLED) {
                return;
            }
            new Thread(() -> {
                if (!key_extracted_icon.isVisible()) {
                    log("Extract or Generate a key first", true);
                    return;
                }

                if (QUICK_PROCESSING && !quick_processing_icon.isVisible()) {
                    log("Setting up Quick Processing...", false);
                    if (SAS_ROSET.setQuickProcessing(true, MainApp.DYNAMIC_KEY, MainApp.STATIC_KEYS)) {
                        quick_processing_icon.setVisible(true);
                    }
                }

                if (INPUT_TYPE == 0) { // text
                    processText();
                } else if (INPUT_TYPE == 1) { // files
                    processFiles();
                }
            }).start();
        } catch (Exception e) {
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] An unexpected error has occurred after clicking 'Process' button:\n"+ e + "\n"));
        }
    }

    private void processText() {
        String[] text_to_process = SAS_ROSET.stringBreaker(input_text_input_field.getText(), '\n', false);
        StringBuilder output = new StringBuilder();

        if (text_to_process.length > 10000) {
            log("Too many lines of text (max is 10,000 lines)",true);
            return;
        }
       disable_next_process_button();
        long startTime = System.currentTimeMillis();
        if (FUNCTION_TYPE == 0) {
            log("Encrypting...", false);
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[*] Encrypting Text...\n"));
             
            for (String eString : text_to_process) {
                if (!eString.isEmpty()) {
                    output.append(SAS_ROSET.rcsTextEncrypt(MainApp.DYNAMIC_KEY, MainApp.STATIC_KEYS, eString)).append("\n");
                } else {
                    output.append("\n");
                }
            }

        } else if (FUNCTION_TYPE == 1) {
            log("Decrypting...", false);
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[*] Decrypting Text...\n"));
            for (String eString : text_to_process) {
                if (!eString.isEmpty()) {
                    output.append(SAS_ROSET.rcsTextDecrypt(MainApp.DYNAMIC_KEY, MainApp.STATIC_KEYS, eString)).append("\n");
                } else {
                    output.append("\n");
                }
            }
        }
        long endTime = System.currentTimeMillis();

        output_text_output_field.setText(output.toString());

        text_to_process = null;
        output.delete(0,output.length()-1); output = null;
        double duration = (double) (endTime - startTime) / 1000.0;
        log("Finished (in "+duration+"s)", false);
        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Finished (in "+duration+"s)\n"));
       enable_next_process_button();
    }

    private void processFiles() {

        // reset values
        MainApp.ALL_FILES_TO_PROCESS.clear();
        MainApp.FILES_PROCESSED = -1;

        if (FILES_TO_PROCESS.isEmpty()) {
            log("Add files to process",true);
            return;
        }

        String outputDirPath = output_directory_file_input.getText();
        if (outputDirPath.isEmpty()) {
            log("Provide an output directory",true);
            return;
        }
        
        int threads = SAS_ROSET.stringToInt(proc_sett_threads_input.getText());
        MainApp.THREADS_PER_FILE = SAS_ROSET.stringToInt(proc_sett_threads_per_file_input.getText());

       disable_next_process_button();
        log("Scanning files...",false);
        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[*] Scanning files...\n"));
        MainApp.FILES_PROCESSING_START = System.currentTimeMillis();

        for (DataFileInput_File value : FILES_TO_PROCESS.values()) {
            File file = new File(value.getPath());
            
            if (file.isDirectory()) {
                Queue<File> queue = new LinkedList<>();

                queue.add(file);

                while (!queue.isEmpty()) {
                    File currentDirectory = queue.poll();

                    File[] files = currentDirectory.listFiles();
                    if (files != null) {
                        for (File eFile : files) {
                            if (eFile.isDirectory()) {
                                queue.add(eFile);
                            } else {
                                MainApp.ALL_FILES_TO_PROCESS.add(eFile);
                                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] "+eFile.getName()+" Added\n"));
                            }
                        }
                    }
                }
            } else if (file.isFile()) {
                MainApp.ALL_FILES_TO_PROCESS.add(file);
            }
        }

        MainApp.startProcessing(threads);

    }



    // function (Custom Radio Button)
    @FXML
    protected void function_encrypt_button_onAction() {
        function_encrypt_button.getStyleClass().clear(); function_encrypt_button.getStyleClass().add("radio_button_rect_selected");
        function_decrypt_button.getStyleClass().clear(); function_decrypt_button.getStyleClass().add("radio_button_rect_unselected");

        key_generate_button.getStyleClass().clear(); key_generate_button.getStyleClass().add("radio_button_rect_unselected");
        FUNCTION_TYPE = 0;

        enable_dissable_algos();
    }
    @FXML
    protected void function_decrypt_button_onAction() {
        function_encrypt_button.getStyleClass().clear(); function_encrypt_button.getStyleClass().add("radio_button_rect_unselected");
        function_decrypt_button.getStyleClass().clear(); function_decrypt_button.getStyleClass().add("radio_button_rect_selected");
        
        select_key_button_onAction();
        key_generate_button.getStyleClass().clear(); key_generate_button.getStyleClass().add("radio_button_rect_disabled");

        FUNCTION_TYPE = 1;

        enable_dissable_algos();
        algo_icon.setText("DEC");
    }



    // key gen and key select boxes highlight
    @FXML
    protected void select_key_button_onAction() {
        key_select_button.getStyleClass().clear(); key_select_button.getStyleClass().add("radio_button_rect_selected");
        if (FUNCTION_TYPE == 0) {
            key_generate_button.getStyleClass().clear(); key_generate_button.getStyleClass().add("radio_button_rect_unselected");
        } else {
            key_generate_button.getStyleClass().clear(); key_generate_button.getStyleClass().add("radio_button_rect_disabled");
        }

        generate_key_box.setVisible(false);
        select_key_box.setVisible(true);

        GENERATE_KEY = false;
        main_next_button.setText("Extract");
    }
    @FXML
    protected void generate_key_button_onAction() {
        if (FUNCTION_TYPE == 0) {

            key_generate_button.getStyleClass().clear(); key_generate_button.getStyleClass().add("radio_button_rect_selected");
            key_select_button.getStyleClass().clear(); key_select_button.getStyleClass().add("radio_button_rect_unselected");

            select_key_box.setVisible(false);
            generate_key_box.setVisible(true);

            GENERATE_KEY = true;
            main_next_button.setText("Generate");
        }
    }


    // ---------- SELECT KEY BOX UI ----------
    // select_key_fs_select_button
    @FXML
    protected void select_key_fs_select_button_onAction() {
        select_key_button_onAction();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open .rosk File");
        Stage stage = (Stage) root.getScene().getWindow();
        FileChooser.ExtensionFilter extensionFilter = new FileChooser.ExtensionFilter("ROSK File (*.rosk)", "*.rosk");
        fileChooser.getExtensionFilters().add(extensionFilter);

        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            select_key_path.setText(selectedFile.getAbsolutePath());
        }
    }

    // Select Key File Drag and Drop
    @FXML
    private void select_key_path_onDragOver(DragEvent event) {
        if (event.getGestureSource() != select_key_path && event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files.size() == 1 && files.get(0).getName().toLowerCase().endsWith(".rosk")) {
                event.acceptTransferModes(TransferMode.COPY);
            }
        }
        event.consume();
    }

    @FXML
    private void select_key_path_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            if (files.size() == 1 && files.get(0).getName().toLowerCase().endsWith(".rosk")) {
                select_key_path.setText(files.get(0).getAbsolutePath());
            }
        }
        event.setDropCompleted(success);
        event.consume();
    }

    // Keystore Drag and Drop
    @FXML
    private void keystore_onDragOver(DragEvent event) {
        if (event.getGestureSource() != select_key_path && event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files.size() == 1 && files.get(0).getName().toLowerCase().endsWith(".rosk")) {
                event.acceptTransferModes(TransferMode.COPY);
            }
        }
        event.consume();
    }

    @FXML
    private void keystore_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            if (files.size() == 1) {
                Path keystore_key_file_path = Paths.get(System.getProperty("user.dir")+"/roset_keystore/"+files.get(0).getName());
                try {
                    //Check key file
                    FileInputStream fileInputStream = new FileInputStream(files.get(0));
                    // Read bytes until newline character is encountered
                    ByteArrayOutputStream metaBytes = new ByteArrayOutputStream();
                    int currentByte;
                    while ((currentByte = fileInputStream.read()) != '\n') {
                        metaBytes.write(currentByte);
                    }

                    // Get Metadata
                    String file_name = metaBytes.toString(StandardCharsets.UTF_8);
                    int kLength = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                    int st_keys = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));
                    int version = MainApp.byteArrayToInt(fileInputStream.readNBytes(4));

                    if (version != MainApp.VERSION_IDENTIFIER) {
                        log("This key file '"+files.get(0).getName()+"' is supported by the ROSET version 'v"+version+".x.x'", true);
                        return;
                    }

                    if (file_name != null && files.get(0).getName().toLowerCase().endsWith(".rosk")) {
                        if ( (fileInputStream.readAllBytes().length-40)/(4*kLength) == st_keys+1) { // count keys
                            clearLog();
                            Files.copy(files.get(0).toPath(), keystore_key_file_path);
                            extract_keyStore_data();
                            MainApp.comcon.log_display.appendText("[+] Successfully copied "+files.get(0).getName()+" to Keystore \n");
                        } else {  log("Invalid key file",true); return;}
                    }

                    metaBytes.close();
                    fileInputStream.close();
                } catch (Exception e) { Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] Error on keystore drop: \n"+e+"\n"));}
            }
        }
        event.setDropCompleted(success);
        event.consume();
    }


    // ---------- GENERATE KEY BOX UI ----------
    // key length
    @FXML
    protected void gk_key_length_bitwise_rb_onAction() {
        gk_key_length_bitwise_rb.getStyleClass().clear(); gk_key_length_bitwise_rb.getStyleClass().add("radio_button_selected");
        gk_key_length_custom_rb.getStyleClass().clear(); gk_key_length_custom_rb.getStyleClass().add("radio_button_unselected");

        GK_KEY_LENGTH_IS_BITWISE = true;
        generate_key_button_onAction();
    }
    @FXML
    protected void gk_key_length_custom_rb_onAction() {
        gk_key_length_custom_rb.getStyleClass().clear(); gk_key_length_custom_rb.getStyleClass().add("radio_button_selected");
        gk_key_length_bitwise_rb.getStyleClass().clear(); gk_key_length_bitwise_rb.getStyleClass().add("radio_button_unselected");

        GK_KEY_LENGTH_IS_BITWISE = false;
        generate_key_button_onAction();
    }

    // RGM Status
    @FXML
    protected void RGM_status_disabled_rb_onAction() { // disable option removed from UI
        RGM_status_full_rb.getStyleClass().clear(); RGM_status_full_rb.getStyleClass().add("radio_button_unselected");
        RGM_status_partial_rb.getStyleClass().clear(); RGM_status_partial_rb.getStyleClass().add("radio_button_unselected");
        //RGM_status_disabled_rb.getStyleClass().clear(); RGM_status_disabled_rb.getStyleClass().add("radio_button_selected");

        GK_RGM_STATUS = 0;
        generate_key_button_onAction();
    }
    @FXML
    protected void RGM_status_partial_rb_onAction() {
        RGM_status_full_rb.getStyleClass().clear(); RGM_status_full_rb.getStyleClass().add("radio_button_unselected");
        RGM_status_partial_rb.getStyleClass().clear(); RGM_status_partial_rb.getStyleClass().add("radio_button_selected");
        //RGM_status_disabled_rb.getStyleClass().clear(); RGM_status_disabled_rb.getStyleClass().add("radio_button_unselected");
        GK_RGM_STATUS = 1;
        generate_key_button_onAction();
    }
    @FXML
    protected void RGM_status_full_rb_onAction() {
        RGM_status_full_rb.getStyleClass().clear(); RGM_status_full_rb.getStyleClass().add("radio_button_selected");
        RGM_status_partial_rb.getStyleClass().clear(); RGM_status_partial_rb.getStyleClass().add("radio_button_unselected");
        //RGM_status_disabled_rb.getStyleClass().clear(); RGM_status_disabled_rb.getStyleClass().add("radio_button_unselected");
        GK_RGM_STATUS = 2;
        generate_key_button_onAction();
    }

    // RGM Base
    @FXML
    protected void RGM_base_s2_rb_onAction() {
        RGM_base_s2_rb.getStyleClass().clear(); RGM_base_s2_rb.getStyleClass().add("radio_button_selected");
        RGM_base_s10_rb.getStyleClass().clear(); RGM_base_s10_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s16_rb.getStyleClass().clear(); RGM_base_s16_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s64_rb.getStyleClass().clear(); RGM_base_s64_rb.getStyleClass().add("radio_button_unselected");

        GK_RGM_BASE = 0;
        generate_key_button_onAction();
    }

    @FXML
    protected void RGM_base_s10_rb_onAction() {
        RGM_base_s2_rb.getStyleClass().clear(); RGM_base_s2_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s10_rb.getStyleClass().clear(); RGM_base_s10_rb.getStyleClass().add("radio_button_selected");
        RGM_base_s16_rb.getStyleClass().clear(); RGM_base_s16_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s64_rb.getStyleClass().clear(); RGM_base_s64_rb.getStyleClass().add("radio_button_unselected");

        GK_RGM_BASE = 1;
        generate_key_button_onAction();
    }

    @FXML
    protected void RGM_base_s16_rb_onAction() {
        RGM_base_s2_rb.getStyleClass().clear(); RGM_base_s2_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s10_rb.getStyleClass().clear(); RGM_base_s10_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s16_rb.getStyleClass().clear(); RGM_base_s16_rb.getStyleClass().add("radio_button_selected");
        RGM_base_s64_rb.getStyleClass().clear(); RGM_base_s64_rb.getStyleClass().add("radio_button_unselected");

        GK_RGM_BASE = 2;
        generate_key_button_onAction();
    }
    @FXML
    protected void RGM_base_s64_rb_onAction() {
        RGM_base_s2_rb.getStyleClass().clear(); RGM_base_s2_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s10_rb.getStyleClass().clear(); RGM_base_s10_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s16_rb.getStyleClass().clear(); RGM_base_s16_rb.getStyleClass().add("radio_button_unselected");
        RGM_base_s64_rb.getStyleClass().clear(); RGM_base_s64_rb.getStyleClass().add("radio_button_selected");

        GK_RGM_BASE = 3;
        generate_key_button_onAction();
    }

    // Random Character Selection
    @FXML
    protected void rand_char_selection_checkbox_onAction() {
        if (GK_RANDOM_CHAR_SELECTION) {
            GK_RANDOM_CHAR_SELECTION = false;
            rand_char_selection_checkbox.getStyleClass().clear(); rand_char_selection_checkbox.getStyleClass().add("check_box_unselected");
        } else {
            GK_RANDOM_CHAR_SELECTION = true;
            rand_char_selection_checkbox.getStyleClass().clear(); rand_char_selection_checkbox.getStyleClass().add("check_box_selected");
        }
        generate_key_button_onAction();
    }

    // Save Key to Keystore
    @FXML
    protected void save_to_keystore_checkbox_onAction() {
        if (GK_SAVE_KEY_TO_KEYSTORE) {
            GK_SAVE_KEY_TO_KEYSTORE = false;
            save_to_keystore_checkbox.getStyleClass().clear(); save_to_keystore_checkbox.getStyleClass().add("check_box_unselected");
        } else {
            GK_SAVE_KEY_TO_KEYSTORE = true;
            save_to_keystore_checkbox.getStyleClass().clear(); save_to_keystore_checkbox.getStyleClass().add("check_box_selected");
        }
        generate_key_button_onAction();
    }


    // ---------- DATA TAB UI ----------
    // input data type (Custom Radio Button)
    @FXML
    protected void input_type_text_button_onAction() {
        input_type_text.getStyleClass().clear(); input_type_text.getStyleClass().add("radio_button_rect_selected");
        input_type_file.getStyleClass().clear(); input_type_file.getStyleClass().add("radio_button_rect_unselected");

        input_file_box.setVisible(false);
        output_file_box.setVisible(false);
        input_text_box.setVisible(true);
        output_text_box.setVisible(true);

        INPUT_TYPE = 0;

        enable_dissable_algos();
        algo_rcs_button_onAction();
    }
    
    @FXML
    protected void input_type_file_button_onAction() {
        input_type_text.getStyleClass().clear(); input_type_text.getStyleClass().add("radio_button_rect_unselected");
        input_type_file.getStyleClass().clear(); input_type_file.getStyleClass().add("radio_button_rect_selected");

        input_text_box.setVisible(false);
        output_text_box.setVisible(false);
        input_file_box.setVisible(true);
        output_file_box.setVisible(true);

        INPUT_TYPE = 1;
        enable_dissable_algos();
    }


    // algorithm to use (Custom Radio Button)
    @FXML
    protected void algo_rcs_button_onAction() {
        if (!RCS_BUTTON_DISABLED) {
            algo_rcs.getStyleClass().clear();algo_rcs.getStyleClass().add("radio_button_rect_selected");
        }

        if (RBS_BUTTON_DISABLED || RBS_UNSUPPORTED) {
            algo_rbs.getStyleClass().clear(); algo_rbs.getStyleClass().add("radio_button_rect_disabled");
        } else {
            algo_rbs.getStyleClass().clear(); algo_rbs.getStyleClass().add("radio_button_rect_unselected");
        }

        ALGORITHM_TO_USE = 0;
        if (FUNCTION_TYPE == 0) {
            algo_icon.setText("RCS");
        } else {
            algo_icon.setText("DEC");
        }
    }
    @FXML
    protected void algo_rbs_button_onAction() {
        if (!RBS_BUTTON_DISABLED && !RBS_UNSUPPORTED) {
            algo_rcs.getStyleClass().clear(); algo_rcs.getStyleClass().add("radio_button_rect_unselected");
            algo_rbs.getStyleClass().clear(); algo_rbs.getStyleClass().add("radio_button_rect_selected");

            ALGORITHM_TO_USE = 1;
            algo_icon.setText("RBS");
        }
    }

    private void enable_dissable_algos() {
        if (INPUT_TYPE == 0) { //text
            RBS_BUTTON_DISABLED = true;
            algo_rbs.getStyleClass().clear(); algo_rbs.getStyleClass().add("radio_button_rect_disabled");

            RCS_BUTTON_DISABLED = false;
            algo_rcs_button_onAction();

        } else { // file
            if (FUNCTION_TYPE == 0) { // encrypt
                RCS_BUTTON_DISABLED = false;
                RBS_BUTTON_DISABLED = false;

                if (ALGORITHM_TO_USE == 0) { //RCS
                    algo_rcs_button_onAction();
                } else if (ALGORITHM_TO_USE == 1) { //RBS
                    algo_rbs_button_onAction();
                }

            } else if (FUNCTION_TYPE == 1) { //decrypt
                RCS_BUTTON_DISABLED = true;
                RBS_BUTTON_DISABLED = true;
                algo_rcs.getStyleClass().clear(); algo_rcs.getStyleClass().add("radio_button_rect_disabled");
                algo_rbs.getStyleClass().clear(); algo_rbs.getStyleClass().add("radio_button_rect_disabled");
            }
        }
    }


    // Input File buttons
    @FXML
    protected void input_file_add_button_onAction() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File To Process");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            fileChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            if (selectedFile.isFile()) {
                String ID = "" + FILES_TO_PROCESS.size();
                FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "FILE", selectedFile.getName(), selectedFile.getAbsolutePath()));
                LAST_VISITED_DIR = selectedFile.getParentFile();
                COMMON_PATH = selectedFile.getParentFile().getAbsolutePath();
                set_process_file_data();
            }
        }
    }

    @FXML
    protected void input_dir_add_button_onAction() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Directory/Folder To Process");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            directoryChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            if (selectedDirectory.isDirectory()) {
                String ID = "" + FILES_TO_PROCESS.size();
                FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "DIR", selectedDirectory.getName(), selectedDirectory.getAbsolutePath()));
                LAST_VISITED_DIR = selectedDirectory.getParentFile();
                COMMON_PATH = selectedDirectory.getParentFile().getAbsolutePath();
                set_process_file_data();
            }
        }
    }

    @FXML
    protected void input_file_remove_button_onAction() {
        //remove file path from list based on the selected row in table
        if (FILES_TO_PROCESS.containsKey(ID_OF_SELECTED_DATA_FILE)) {
            FILES_TO_PROCESS.remove(ID_OF_SELECTED_DATA_FILE);
            set_process_file_data();
            input_file_remove_button.getStyleClass().clear(); input_file_remove_button.getStyleClass().add("disabled_button");
        }
    }

    private void set_process_file_data() {
        new Thread( () -> {
            ObservableList<DataFileInput_File> dataFileInput_files = FXCollections.observableArrayList();

            for(Map.Entry<String, DataFileInput_File> entry : FILES_TO_PROCESS.entrySet()) {
                DataFileInput_File dif = entry.getValue();
                dataFileInput_files.add(dif);
            }

            input_file_table.setItems(dataFileInput_files);

        }).start();
    }

    // Input File Drag and Drop
    @FXML
    private void input_file_onDragOver(DragEvent event) {
        if (event.getGestureSource() != input_file_table && event.getDragboard().hasFiles()) {
            event.acceptTransferModes(TransferMode.COPY);
        }
        event.consume();
    }

    @FXML
    private void input_file_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            COMMON_PATH = files.get(0).getParentFile().getAbsolutePath();
            
            for (File eFile: files) {
                if (eFile.isFile()) {
                    String ID = "" + FILES_TO_PROCESS.size();
                    FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "FILE", eFile.getName(), eFile.getAbsolutePath()));
                } else if (eFile.isDirectory()) {
                    String ID = "" + FILES_TO_PROCESS.size();
                    FILES_TO_PROCESS.put(ID, new DataFileInput_File(ID, "DIR", eFile.getName(), eFile.getAbsolutePath()));
                }
            }
            set_process_file_data();
        }
        event.setDropCompleted(success);
        event.consume();
    }



    // Output directory select
    @FXML
    protected void output_directory_select_button_onAction() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Output Directory/Folder");
        Stage stage = (Stage) root.getScene().getWindow();

        if (LAST_VISITED_DIR != null) {
            directoryChooser.setInitialDirectory(LAST_VISITED_DIR);
        }

        File selectedDirectory = directoryChooser.showDialog(stage);

        if (selectedDirectory != null) {
            if (selectedDirectory.isDirectory()) {
                output_directory_file_input.setText(selectedDirectory.getAbsolutePath());
                OUTPUT_DIR = selectedDirectory.getAbsolutePath();
                LAST_VISITED_DIR = selectedDirectory.getParentFile();
            }
        }
    }

    // Output Directory Drag and Drop
    @FXML
    private void output_directory_path_onDragOver(DragEvent event) {
        if (event.getGestureSource() != select_key_path && event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files.size() == 1 && files.get(0).isDirectory()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
        }
        event.consume();
    }

    @FXML
    private void output_directory_path_onDragDropped(DragEvent event) {
        Dragboard db = event.getDragboard();
        boolean success = false;
        if (db.hasFiles()) {
            success = true;
            List<File> files = db.getFiles();

            if (files.size() == 1 && files.get(0).isDirectory()) {
                output_directory_file_input.setText(files.get(0).getAbsolutePath());
                OUTPUT_DIR = files.get(0).getAbsolutePath();
            }
        }
        event.setDropCompleted(success);
        event.consume();
    }

    // Invalid key protection
    @FXML
    protected void invalid_key_protection_checkbox_onAction() {
        if (INVALID_KEY_PROTECTION) {
            INVALID_KEY_PROTECTION = false;
            invalid_key_protection_checkbox.getStyleClass().clear(); invalid_key_protection_checkbox.getStyleClass().add("check_box_unselected");
            clearLogCondition("Note: Enabling 'invalid key protection' may reduce security");
        } else {
            INVALID_KEY_PROTECTION = true;
            invalid_key_protection_checkbox.getStyleClass().clear(); invalid_key_protection_checkbox.getStyleClass().add("check_box_selected");
            log("Note: Enabling 'invalid key protection' may reduce security",false);
        }
    }

    // Quick processing
    @FXML
    protected void quick_processing_checkbox_onAction() {
        if (QUICK_PROCESSING) {
            QUICK_PROCESSING = false;
            SAS_ROSET.QUICK_PROCESSING = false;
            quick_processing_checkbox.getStyleClass().clear(); quick_processing_checkbox.getStyleClass().add("check_box_unselected");
            quick_processing_icon.setVisible(false);
        } else {
            QUICK_PROCESSING = true;
            quick_processing_checkbox.getStyleClass().clear(); quick_processing_checkbox.getStyleClass().add("check_box_selected");
        }
    }

    // Encrypt file names
    @FXML
    protected void random_file_names_checkbox_onAction() {
        if (RANDOM_FILE_NAMES) {
            RANDOM_FILE_NAMES = false;
            random_file_names_checkbox.getStyleClass().clear(); random_file_names_checkbox.getStyleClass().add("check_box_unselected");
        } else {
            RANDOM_FILE_NAMES = true;
            random_file_names_checkbox.getStyleClass().clear(); random_file_names_checkbox.getStyleClass().add("check_box_selected");
        }
    }


    // Additional support methods
    protected static void log(String msg, boolean isError) {
        if (isError) {
            msg_text_STATIC.setFill(Color.web("#e43737"));
        } else {
            msg_text_STATIC.setFill(Color.web("#aaaaaa"));
        }
        msg_text_STATIC.setText(msg);
    }

    protected static void clearLog() {
        msg_text_STATIC.setText("");
    }

    protected static void clearLogCondition(String equalsString) {
        if (msg_text_STATIC.getText().equals(equalsString)) {
            msg_text_STATIC.setText("");
        }
    }

}

