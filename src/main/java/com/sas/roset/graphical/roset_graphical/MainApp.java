package com.sas.roset.graphical.roset_graphical;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.awt.*;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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

public class MainApp extends Application {

    public static final String VERSION = "v1.0.0";
    public static final int VERSION_IDENTIFIER = 1;     // This is the 'X' value in the version format 'vX.Y.Z'
                                                        // when this value changes, the ROSET Graphical version will no longer be backwards compatible

    private double x,y, x_log,y_log, x_wel,y_wel = 0;
    protected static boolean firstTime = false;

    protected static ComCon comcon;
    private static Stage logWin;
    protected static boolean LOG_WIN_SHOWN = false;

    protected static int[] STATIC_KEYS;
    private static int static_keys_extracted = 0;
    protected static int DYNAMIC_KEY = 0;

    protected static ArrayList<File> ALL_FILES_TO_PROCESS = new ArrayList<>();
    protected static int FILES_PROCESSED = -1;
    protected static long FILES_PROCESSING_START = 0;
    
    private static boolean ERROR_DURING_PROCESSING = false;

    protected static int THREADS_PER_FILE = 4; // can be changed via UI
    private static final int MAX_RCS_BUFFER_SIZE = 5120;
    private static final int MAX_RBS_BUFFER_SIZE = 5120;

    private static long totalBytesProcessed = 0;

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String[] IKP_PHRASES = {
            "SaS_RoSEtajiJjiLap_nBBNzpIIa_09pkugVTDRpkugVTDiJjiLap__0pkugVTDR9)s_R)_ssSRrr",
            "mnBBNzpIIajiJjiLap__09)9*JpkugViJjiLap__0pkugVTDR9)s_TDRbd$%j=9hakk1fvja",
            "roSEtsAajiJjiLap__0pkugVTDiJjiLap__0pkugVTDR9)s_R9)s_s",
            "ajiJjiLap__09pkugVTDR)(iJjiLap__0pkugVTDR9)s_iJjiLap__0pkugVTDR9)s_)jan/a",
            "s_S_RsTs_S_RsTs_S_RsTsiJjiLap__0pkugVTDR9)iJjiLap__0pkugVTDR9)s_s__S_RsTs_S_RajiJjiLap__09)sTs_S_RsTs_S_RsTs_S_RsT",
            "SSro__iJjiLap__0pkugVTDR9)s_seETtiJjiLap__0pkugVTDR9)s__saSs_pkugVTDRroEt",
            "sAajiJjiLap__09iJjiLap__0pkugVTDR9)s_)SpkugVTDR_Rp__0pkugVTDR9)s_kugVTDRDRosET",
            "Tniapm_8aaiJjiLap__0pkugVTDR9)s_jiJjiLap__09)jhg)p__0pkugVTDR9)s_kugVTDRDRjsmmla;sm__smmn",
            "Tniapmp__0pkugVTDR9)s_kugVTDRDR_8aaiJjiLap__0pkugVTDR9)s_jiJjiLap__09)jhg)jsmmla;sm__smmn",
            "pkugVTpkugVTDRpiJjiLap__0pkugVTDR9)s_kugVTDRDR"
    };

    

    public static void main(String[] args) {
        launch();
    }

    @Override
    public void start(Stage stage) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("main_layout.fxml")));
        Scene scene = new Scene(root, 800, 600);

        stage.setMinWidth(800);
        stage.setMinHeight(600);
        stage.setResizable(false);
        stage.setTitle("SAS-ROSET");
        stage.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("ROSET_ICON_8_rect_36r.png"))));
        stage.initStyle(StageStyle.UNDECORATED);

        root.setOnMousePressed(event -> {
            x = event.getSceneX();
            y = event.getSceneY();
        });

        root.setOnMouseDragged(event -> {
            stage.setX(event.getScreenX() - x);
            stage.setY(event.getScreenY() - y);
        });

        stage.setScene(scene);
        stage.show();

        Platform.runLater(() -> {
            try {
                setLogWin();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            showWelcomeWin();
        });
    }

    protected static void goToHelp(){
        openLink("https://sas-roset.github.io/docs/graphical/graphical.html");
    }

    protected static void goToTerms(){
            openLink("https://sas-roset.github.io/legal/terms.html");
    }

    protected static void openLink(String URL){
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("linux") || os.contains("nix") || os.contains("nux")) { //Linux
                String[] commands = {
                        "xdg-open",
                        "firefox",
                        "google-chrome",
                        "sensible-browser",
                        "kde-open"
                };

                for (String command : commands) {
                        try {
                            Process process = new ProcessBuilder(command, URL).start();
                            return;
                        } catch (Exception ignored) {}
                }
                MainController.log("Go to ("+URL+")",false);

            } else if (os.contains("win")) { //Windows
                Process process = new ProcessBuilder("cmd", "/c", "start", URL).start();

            } else if (os.contains("mac")) { //MacOS
                Process process = new ProcessBuilder("open", URL).start();

            } else {
                MainController.log("Go to ("+URL+")",false);
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] Cannot open link on this platform\n"));
            }
        } catch (Exception e) {
            MainController.log("Go to ("+URL+")",false);
            Platform.runLater(() -> MainApp.comcon.log_display.appendText("[!] An unexpected error has occurred while opening link:\n" + e + "\n"));
        }
    }

    private void showWelcomeWin() {
        if (firstTime) {
            try {
                Stage welWin = new Stage();
                // Load the FXML for the welcome window
                Parent root = new FXMLLoader(Objects.requireNonNull(getClass().getResource("welcome_layout.fxml"))).load();
                Scene scene = new Scene(root, 430, 250);

                // Configure the Stage
                welWin.setMinWidth(430);
                welWin.setMinHeight(250);
                welWin.setResizable(false);
                welWin.setTitle("Welcome");
                welWin.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("ROSET_ICON_8_rect_36r.png"))));
                welWin.initStyle(StageStyle.UNDECORATED);

                // Set up dragging functionality
                root.setOnMousePressed(event -> {
                    x_wel = event.getSceneX();
                    y_wel = event.getSceneY();
                });

                root.setOnMouseDragged(event -> {
                    welWin.setX(event.getScreenX() - x_wel);
                    welWin.setY(event.getScreenY() - y_wel);
                });

                // Set the scene and show the window
                welWin.setScene(scene);
                welWin.show();
            } catch (Exception e) {
                Platform.runLater(() -> comcon.log_display.appendText("[!] Failed to load welcome window: " + e.getMessage()));
            }
        }
    }


    private void setLogWin() throws IOException {
        logWin = new Stage();
        FXMLLoader loader = new FXMLLoader(Objects.requireNonNull(getClass().getResource("log_layout.fxml")));
        Parent root = loader.load();
        comcon = loader.getController();
        Scene scene = new Scene(root, 430, 600);

        logWin.setMinWidth(430);
        logWin.setMinHeight(600);
        logWin.setResizable(false);
        logWin.setTitle("Logs");
        logWin.getIcons().add(new Image(Objects.requireNonNull(getClass().getResourceAsStream("ROSET_ICON_8_rect_36r.png"))));
        logWin.initStyle(StageStyle.UNDECORATED);

        root.setOnMousePressed(event -> {
            x_log = event.getSceneX();
            y_log = event.getSceneY();
        });

        root.setOnMouseDragged(event -> {
            logWin.setX(event.getScreenX() - x_log);
            logWin.setY(event.getScreenY() - y_log);
        });

        logWin.setScene(scene);
        Platform.runLater(() -> comcon.log_display.appendText("SAS-ROSET Graphical "+MainApp.VERSION+"  [API: "+SAS_ROSET.API_VERSION+"]\nDeveloped by saaiqSAS, Licensed under GNU GPLv3\n(https://sas-roset.github.io)\n\n"));
    }

    protected static void showLogWin() {
        if (LOG_WIN_SHOWN) {
            logWin.hide();
        } else {
            logWin.show();
        }
        LOG_WIN_SHOWN = !LOG_WIN_SHOWN;

    }

    // ---------- Keys and Key File Methods ----------
    protected static boolean generateKeyFile(int kLength, int kForEach, int kAdd, int stKeys) {
        try {
            if (MainController.KEY_SAVE_FILE.createNewFile()) {
                FileOutputStream fileOutputStream = new FileOutputStream(MainController.KEY_SAVE_FILE);
                fileOutputStream.write( intArrayToByteArray( (MainController.KEY_SAVE_FILE.getName().replace(".rosk", "")+"\n").codePoints().toArray() )); // save meta to key file

                fileOutputStream.write(intToByteArray(kLength)); // 4 bytes
                fileOutputStream.write(intToByteArray(stKeys)); // 4 bytes
                fileOutputStream.write(intToByteArray(VERSION_IDENTIFIER)); // 4 bytes

                long st = System.currentTimeMillis();
                int[] Dyn = SAS_ROSET.generateDynamicKey(kLength,MainController.GK_RGM_STATUS,MainController.GK_RGM_BASE,kForEach,kAdd,MainController.GK_RANDOM_CHAR_SELECTION);
                double d1 = (double) (System.currentTimeMillis() - st) / 1000.0;
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Dynamic Key generated (in "+ d1 +"s)\n"));

                st = System.currentTimeMillis();
                fileOutputStream.write(intArrayToByteArray(Dyn)); // save dynamic key to key file
                double d2 = (double) (System.currentTimeMillis() - st) / 1000.0;
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Dynamic Key written to file (in "+ d2 +"s)\n"));

                st = System.currentTimeMillis();
                DYNAMIC_KEY = SAS_ROSET.extractDynamicKey(Dyn); // extract dynamic key
                double d3 = (double) (System.currentTimeMillis() - st) / 1000.0;
                Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Dynamic Key extracted to memory (in "+ d3 +"s)\n"));

                Dyn = null;

                if (DYNAMIC_KEY != 9999) {
                    STATIC_KEYS = new int[stKeys+(stKeys/2)];
                    SAS_ROSET.initializeStaticKeyStorage((stKeys+(stKeys/2)),kLength);
                    static_keys_extracted = 0;

                    for (int i = 0; i < stKeys; i++) {
                        st = System.currentTimeMillis();
                        int[] St = SAS_ROSET.generateStaticKey(kLength);
                        double d4 = (double) (System.currentTimeMillis() - st) / 1000.0;
                        int finalI = i+1;
                        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Static Key "+ finalI +" generated (in "+ d4 +"s)\n"));

                        st = System.currentTimeMillis();
                        fileOutputStream.write(intArrayToByteArray(St)); // save static key to key file
                        double d5 = (double) (System.currentTimeMillis() - st) / 1000.0;
                        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Static Key "+ finalI +" written to file (in "+ d5 +"s)\n"));

                        st = System.currentTimeMillis();
                        STATIC_KEYS[static_keys_extracted] = SAS_ROSET.extractStaticKey(St); // extract static key
                        double d6 = (double) (System.currentTimeMillis() - st) / 1000.0;
                        Platform.runLater(() -> MainApp.comcon.log_display.appendText("[+] Static Key "+ finalI +" extracted to memory (in "+ d6 +"s)\n"));

                        St = null;
                        static_keys_extracted++;
                    }
                    fileOutputStream.close();

                    // extract the reverse St keys
                    extractReverseStaticKeys(SAS_ROSET.getDynamicSetting(DYNAMIC_KEY,1), stKeys);
                    return true;
                } else { fileOutputStream.close(); deleteFile(MainController.KEY_SAVE_FILE); return false;}
            } else { deleteFile(MainController.KEY_SAVE_FILE); return false; }
        } catch (Exception e) {
            Platform.runLater(() -> comcon.log_display.appendText("[!] "+e+"\n"));
            deleteFile(MainController.KEY_SAVE_FILE); return false;
        }
    }

    protected static boolean extractKeys(int[] dyn_key, int[][] st_keys) {
        DYNAMIC_KEY = SAS_ROSET.extractDynamicKey(dyn_key); // extract dynamic key

        if (DYNAMIC_KEY != 9999) {
            STATIC_KEYS = new int[st_keys.length+(st_keys.length/2)];
            SAS_ROSET.initializeStaticKeyStorage(st_keys.length+(st_keys.length/2), st_keys[0].length);

            static_keys_extracted = 0;
            for (int i = 0; i < st_keys.length; i++) {
                STATIC_KEYS[i] = SAS_ROSET.extractStaticKey(st_keys[i]); // extract static key
                static_keys_extracted++;
            }
            // extract the reverse St keys
            extractReverseStaticKeys(SAS_ROSET.getDynamicSetting(DYNAMIC_KEY,1), st_keys.length);
            return true;
        }
        return false;
    }

    private static void extractReverseStaticKeys(int rev_num, int num_of_st_keys) {
        int num_keys_to_rev = num_of_st_keys/2;
        for (int i = 0; i < num_keys_to_rev; i++) {
            switch (rev_num) {
                case 0 -> // top -> bottom
                        STATIC_KEYS[static_keys_extracted] = SAS_ROSET.extractStaticKeyReversed(i);
                case 1 -> // bottom -> top
                        STATIC_KEYS[static_keys_extracted] = SAS_ROSET.extractStaticKeyReversed( num_of_st_keys - (i+1) );
                case 2 -> // center -> bottom
                        STATIC_KEYS[static_keys_extracted] = SAS_ROSET.extractStaticKeyReversed(num_keys_to_rev + i);
                case 3 -> // center -> top
                        STATIC_KEYS[static_keys_extracted] = SAS_ROSET.extractStaticKeyReversed(num_keys_to_rev - (i+1));
            }
            static_keys_extracted++;
        }
    }


    // ---------- Files Processing Methods ----------
    protected static void startProcessing(int threads) {
        ExecutorService  executor = Executors.newFixedThreadPool(threads);
        totalBytesProcessed = 0; // reset

        if (MainController.FUNCTION_TYPE == 0) { // Encrypt
            notifyFileProcessed(false); // start UI notification
            if (MainController.ALGORITHM_TO_USE == 0) { // RCS

                for (File eFile: ALL_FILES_TO_PROCESS) {
                    executor.submit(() ->  MainApp.encryptFile(eFile, true));
                }

            } else if (MainController.ALGORITHM_TO_USE == 1) { // RBS

                for (File eFile: ALL_FILES_TO_PROCESS) {
                    executor.submit(() ->  MainApp.encryptFile(eFile, false));
                }

            }

        } else if (MainController.FUNCTION_TYPE == 1) { // Decrypt
            notifyFileProcessed(true); // start UI notification
            for (File eFile: ALL_FILES_TO_PROCESS) {
                executor.submit(() ->  MainApp.decryptFile(eFile));
            }
        }

    }

    protected static void encryptFile(File eFile, boolean algoIsRCS) {
            SecureRandom rand = new SecureRandom();

                try {
                    long fileSizeInBytes = eFile.length(); // get file size to display in logs
                    totalBytesProcessed += fileSizeInBytes;
                    String stringSize = (fileSizeInBytes < 1024) ? fileSizeInBytes + " Bytes" :
                                        (fileSizeInBytes < 1048576) ? String.format("%.2f KB", fileSizeInBytes / 1024.0) :
                                        (fileSizeInBytes < 1073741824) ? String.format("%.2f MB", fileSizeInBytes / 1048576.0) :
                                                String.format("%.2f GB", fileSizeInBytes / 1073741824.0);

                    Platform.runLater(() -> comcon.log_display.appendText("[*] Encrypting "+eFile.getName()+" ("+stringSize+") \n"));
                    FileInputStream fileInputStream = new FileInputStream(eFile);

                    // Setup Output File
                    File outputFile;
                    if (MainController.RANDOM_FILE_NAMES) {
                        outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getParentFile().getAbsolutePath().replace(MainController.COMMON_PATH,"")+"/"+generateRandomString(rand.nextInt(10)+5)+".ros");
                        while (outputFile.exists()) {
                            outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getParentFile().getAbsolutePath().replace(MainController.COMMON_PATH,"")+"/"+generateRandomString(rand.nextInt(10)+5)+".ros");
                        }
                    } else {
                        outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getAbsolutePath().replace(MainController.COMMON_PATH,"")+".ros");
                    }
                    outputFile.getParentFile().mkdirs();
                    FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
                    BufferedWriter outputFile_write = new BufferedWriter(new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8));


                    // Create Encrypted Metadata
                    String filename = SAS_ROSET.rcsTextEncrypt(DYNAMIC_KEY, STATIC_KEYS, eFile.getName());
                    String algo; // algo used identifier
                    if (algoIsRCS) {
                        algo = SAS_ROSET.getCharFromDynamicKey(DYNAMIC_KEY,3,2); // RCS
                    } else {
                        algo = SAS_ROSET.getCharFromDynamicKey(DYNAMIC_KEY,3,3); //RBS
                    }

                    if (MainController.INVALID_KEY_PROTECTION) {
                        String ikp = SAS_ROSET.rcsTextEncrypt(DYNAMIC_KEY,STATIC_KEYS, IKP_PHRASES[rand.nextInt(5)]);
                        String serp = SAS_ROSET.getExternalChar(filename+algo+ikp);
                        outputFile_write.write(filename+serp + algo+serp +ikp+serp); // write encrypted metadata

                    } else  {
                        String serp = SAS_ROSET.getExternalChar(filename+algo);
                        outputFile_write.write(filename+serp + algo+serp); // write encrypted metadata
                    }

                    // Encrypt File
                    ExecutorService executor = Executors.newFixedThreadPool(THREADS_PER_FILE);
                    boolean finished = false;

                    if (algoIsRCS) { // SAS-RCS
                        List<Future<String>> futures = new ArrayList<>();
                        int buffer = (MAX_RCS_BUFFER_SIZE/3)*3;// get appropriate buffer size

                        while (!finished) {
                            for (int p = 0; p < THREADS_PER_FILE; p++) { // concurrently process 'THREADS_PER_FILE' number of data at a time
                                byte[] data = fileInputStream.readNBytes(buffer); // read data

                                if (data.length > 0) {
                                    futures.add(executor.submit(() -> SAS_ROSET.rcsByteEncrypt(DYNAMIC_KEY, STATIC_KEYS, data)));

                                } else { // end of file
                                    finished = true; // out of while loop
                                    p = THREADS_PER_FILE; // out of for loop
                                }
                            }

                            for(Future<String> future: futures) { // orderly write to output file
                                outputFile_write.write("\n" + future.get());
                            }
                            futures.clear(); // empty list
                        }

                    } else { // SAS-RBS
                        outputFile_write.write("\n");
                        outputFile_write.flush();
                        List<Future<byte[]>> futures = new ArrayList<>();
                        int buffer = SAS_ROSET.rbsNumberOfBytesToPass(DYNAMIC_KEY, MAX_RBS_BUFFER_SIZE, false); // get appropriate buffer size

                        while (!finished) {
                            for (int p = 0; p < THREADS_PER_FILE; p++) { // concurrently process 'parts' number of data at a time
                                byte[] data = fileInputStream.readNBytes(buffer); // read data

                                if (data.length > 0) {
                                    futures.add(executor.submit(() -> SAS_ROSET.rbsByteEncrypt(DYNAMIC_KEY, STATIC_KEYS, MAX_RBS_BUFFER_SIZE, data)));

                                } else { // end of file
                                    finished = true; // out of while loop
                                    p = THREADS_PER_FILE; // out of for loop
                                }
                            }

                            for(Future<byte[]> future: futures) { // orderly write to output file
                                fileOutputStream.write(future.get());
                            }
                            futures.clear(); // empty list
                        }
                    }

                    outputFile_write.close();
                    fileInputStream.close();
                    fileOutputStream.close();
                    notifyFileProcessed(false);

                } catch (Exception e) {
                    ERROR_DURING_PROCESSING = true;
                    Platform.runLater(() -> comcon.log_display.appendText("[!] "+eFile.getPath()+" Could Not Be Encrypted Correctly\n"+"[!]"+e+"\n"));
                    notifyFileProcessed(false);
                }

    }

    protected static void decryptFile(File eFile) {
                try {
                    long fileSizeInBytes = eFile.length(); // get file size to display in logs
                    totalBytesProcessed += fileSizeInBytes;
                    String stringSize = (fileSizeInBytes < 1024) ? fileSizeInBytes + " Bytes" :
                                        (fileSizeInBytes < 1048576) ? String.format("%.2f KB", fileSizeInBytes / 1024.0) :
                                        (fileSizeInBytes < 1073741824) ? String.format("%.2f MB", fileSizeInBytes / 1048576.0) :
                                            String.format("%.2f GB", fileSizeInBytes / 1073741824.0);

                    Platform.runLater(() -> comcon.log_display.appendText("[*] Decrypting "+eFile.getName()+" ("+stringSize+") \n"));
                    FileInputStream fileInputStream = new FileInputStream(eFile);

                    // Read bytes until newline character is encountered
                    ByteArrayOutputStream metaBytes = new ByteArrayOutputStream();
                    int currentByte;
                    while ((currentByte = fileInputStream.read()) != '\n') {
                        metaBytes.write(currentByte);
                    }

                    // Get Metadata
                    String meta = metaBytes.toString(StandardCharsets.UTF_8);
                    String[] metadata = SAS_ROSET.stringBreaker(meta, meta.charAt(meta.length()-1) ,true); // read metadata line
                    meta = null;

                    // identify algo used to encrypt file
                    boolean algoIsRCS = metadata[1].equals(SAS_ROSET.getCharFromDynamicKey(DYNAMIC_KEY,3,2)); // RCS

                    if (metadata.length == 3) { // if invalid key protection phrase is present
                        String ikp_phrase =  SAS_ROSET.rcsTextDecrypt(DYNAMIC_KEY,STATIC_KEYS,metadata[2]);
                        boolean valid = false;
                        for (String eString: IKP_PHRASES) {
                            if (eString.equals(ikp_phrase)) {
                                valid = true;
                                break;
                            }
                        }
                        if (!valid) {
                            ERROR_DURING_PROCESSING = true;
                            Platform.runLater(() -> comcon.log_display.appendText("[!] "+eFile.getPath()+" Could Not Be Decrypted Due To Invalid Key\n"));
                            notifyFileProcessed(true);
                            return;}
                    }

                    // Setup Output File
                    String outputFileName = SAS_ROSET.rcsTextDecrypt(DYNAMIC_KEY,STATIC_KEYS,metadata[0]);
                    File outputFile = new File(MainController.OUTPUT_DIR + "/" + eFile.getParentFile().getAbsolutePath().replace(MainController.COMMON_PATH,"")+"/"+outputFileName);
                    outputFile.getParentFile().mkdirs();
                    FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

                    // Decrypt
                    ExecutorService executor = Executors.newFixedThreadPool(THREADS_PER_FILE);
                    boolean finished = false;


                    if (algoIsRCS) { // RCS
                        BufferedReader eFile_read = new BufferedReader(new InputStreamReader(fileInputStream, StandardCharsets.UTF_8));
                        List<Future<byte[]>> futures = new ArrayList<>();

                        while (!finished) {
                            for (int p = 0; p < THREADS_PER_FILE; p++) { // concurrently process 'parts' number of data at a time
                                String line = eFile_read.readLine(); // read line

                                if (line != null) {
                                    futures.add(executor.submit(() -> SAS_ROSET.rcsByteDecrypt(DYNAMIC_KEY, STATIC_KEYS, line)));

                                } else { // end of file
                                    finished = true; // out of while loop
                                    p = THREADS_PER_FILE; // out of for loop
                                }
                            }


                            for(Future<byte[]> future: futures) { // orderly write to output file
                                fileOutputStream.write(future.get());
                            }
                            futures.clear(); // empty list
                        }
                        eFile_read.close();

                    } else { // RBS
                        List<Future<byte[]>> futures = new ArrayList<>();
                        int buffer = SAS_ROSET.rbsNumberOfBytesToPass(DYNAMIC_KEY, MAX_RBS_BUFFER_SIZE, true); // get appropriate buffer size

                        while (!finished) {
                            for (int p = 0; p < THREADS_PER_FILE; p++) { // concurrently process 'parts' number of data at a time
                                byte[] data = fileInputStream.readNBytes(buffer); // read data

                                if (data.length > 0) {
                                    futures.add(executor.submit(() -> SAS_ROSET.rbsByteDecrypt(DYNAMIC_KEY, STATIC_KEYS, MAX_RBS_BUFFER_SIZE, data)));

                                } else { // end of file
                                    finished = true; // out of while loop
                                    p = THREADS_PER_FILE; // out of for loop
                                }
                            }

                            for(Future<byte[]> future: futures) { // orderly write to output file
                                fileOutputStream.write(future.get());
                            }
                            futures.clear(); // empty list
                        }
                    }

                    fileInputStream.close();
                    fileOutputStream.close();
                    notifyFileProcessed(true);

                } catch (Exception e) {
                    ERROR_DURING_PROCESSING = true;
                    Platform.runLater(() -> comcon.log_display.appendText("[!] "+eFile.getPath()+" Could Not Be Decrypted Correctly\n"+"[!]"+e+"\n"));
                    notifyFileProcessed(true);
                }
    }

    private static void notifyFileProcessed(boolean isDecrypt) {
        FILES_PROCESSED++;
        if (FILES_PROCESSED < ALL_FILES_TO_PROCESS.size()) {
            if (!isDecrypt) {
                MainController.log("Encrypting...(" + FILES_PROCESSED + "/" + ALL_FILES_TO_PROCESS.size() + " files completed)", false);
            } else {
                MainController.log("Decrypting...(" + FILES_PROCESSED + "/" + ALL_FILES_TO_PROCESS.size() + " files completed)", false);
            }
        } else {
            double duration = (double) (System.currentTimeMillis() - FILES_PROCESSING_START) / 1000.0;
            String totalSizeProcessed = (totalBytesProcessed < 1024) ? totalBytesProcessed + " Bytes" :
                                        (totalBytesProcessed < 1048576) ? String.format("%.2f KB", totalBytesProcessed / 1024.0) :
                                        (totalBytesProcessed < 1073741824) ? String.format("%.2f MB", totalBytesProcessed / 1048576.0) :
                                        String.format("%.2f GB", totalBytesProcessed / 1073741824.0);

            if (ERROR_DURING_PROCESSING) {
                MainController.log("Finished (in " + duration + "secs), with Errors", false);
                Platform.runLater(() -> comcon.log_display.appendText("[!] Finished ("+totalSizeProcessed+" in " + duration + "secs), with Errors\n"));
            } else {
                MainController.log("Finished (in " + duration + "secs)", false);
                Platform.runLater(() -> comcon.log_display.appendText("[+] Finished ("+totalSizeProcessed+" in " + duration + "secs)\n"));
            }
            MainController.enable_next_process_button();
        }
    }

    // ---------- Additional Support Methods ----------
    private static boolean isCommandAvailableLinux(String command) {
        try {
            Process process = new ProcessBuilder("which", command).start();
            process.waitFor();
            return process.exitValue() == 0;  // If exit code is 0, command is found
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    public static boolean deleteFile(File file) {
        if (file.isDirectory()) {
            for (File subFile : Objects.requireNonNull(file.listFiles())) {
                deleteFile(subFile);
            }
        }
        return file.delete();
    }

    private static String generateRandomString(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(CHARACTERS.length());
            char randomChar = CHARACTERS.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }

    protected static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte) (value >> 24), // Get the highest byte
                (byte) (value >> 16), // Get the second byte
                (byte) (value >> 8),  // Get the third byte
                (byte) value          // Get the lowest byte
        };
    }

    protected static int byteArrayToInt(byte[] byteArray) {
        if (byteArray.length != 4) {
            throw new IllegalArgumentException("Byte array must be of length 4");
        }
        return ((byteArray[0] & 0xFF) << 24) |
                ((byteArray[1] & 0xFF) << 16) |
                ((byteArray[2] & 0xFF) << 8) |
                (byteArray[3] & 0xFF);
    }

    protected static byte[] intArrayToByteArray(int[] intArray) {
        byte[] byteArray = new byte[intArray.length * 4];
        for (int i = 0; i < intArray.length; i++) {
            byteArray[i * 4] = (byte) (intArray[i] >> 24);
            byteArray[i * 4 + 1] = (byte) (intArray[i] >> 16);
            byteArray[i * 4 + 2] = (byte) (intArray[i] >> 8);
            byteArray[i * 4 + 3] = (byte) intArray[i];
        }
        return byteArray;
    }

    protected static int[] byteArrayToIntArray(byte[] byteArray) {
        if (byteArray.length % 4 != 0) {
            throw new IllegalArgumentException("Byte array length must be a multiple of 4");
        }
        int[] intArray = new int[byteArray.length / 4];
        for (int i = 0; i < intArray.length; i++) {
            intArray[i] = ((byteArray[i * 4] & 0xFF) << 24) |
                    ((byteArray[i * 4 + 1] & 0xFF) << 16) |
                    ((byteArray[i * 4 + 2] & 0xFF) << 8) |
                    (byteArray[i * 4 + 3] & 0xFF);
        }
        return intArray;
    }

}