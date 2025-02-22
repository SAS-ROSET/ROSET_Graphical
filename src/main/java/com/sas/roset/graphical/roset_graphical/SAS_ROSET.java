package com.sas.roset.graphical.roset_graphical;

import java.security.SecureRandom;
import java.util.*;

public class SAS_ROSET {
    protected static final char VERSION_IDENTIFIER = '1';   // this is X in the version format vX.Y.Z.
    // when this value changes, the API will no longer be backwards compatible
    protected static final String API_VERSION = "v1.0.0";
    /*
    ============================================================
    =  |\                                                      =
    =  | \                                                     =
    =  |  \                                                    =
    =  | / \ |  Rrrrr    ooooo    ssssss  EEEEEEE  TTTTTTTTTT  =
    =  |/__ \|  R    R  O     O  S        E            tt      =
    =  |\ | /|  Rrrrr   O     O   Sssss   Eeeeee       tt      =
    =  | \ / |  R    R  O     O        S  E            tt      =
    =     \  |  R     R  ooooo   sssssS   EEEEEEE      tt      =
    =      \ |                                                 =
    =       \|            Java API v1.0.0                     =
    ============================================================

    +---------------------------------------------------------------------------------------------------------------+
    |   > SAS-ROSET project is founded and maintained by...                                                                        |
    |                                                                                                               |
    |   > Original code for the SAS-ROSET Java API is developed by...                                               |
    |                                                                                                               |
    |   > SAS-ROS Cipher, SAS-RCS Algorithm, SAS-RBS Algorithm,                                                     |
    |     SAS-DROS Cipher, and SAS-RGM Algorithm used in this API                                                   |
    |     are developed by...                                                                                       |
    |                                                                                                               |
    |   = ...saaiqSAS (Saaiq Abdulla Saeed) [https://saaiqsas.github.io]                                            |
    +---------------------------------------------------------------------------------------------------------------+


    SAS-ROSET Java API is Licensed under The MIT License
    +---------------------------------------------------------------------------------------------------------------+
    |    The MIT License (MIT)                                                                                      |
    |                                                                                                               |
    |    Copyright © 2025-Present Saaiq Abdulla Saeed                                                                       |
    |                                                                                                               |
    |    Permission is hereby granted, free of charge, to any person obtaining a copy of this software              |
    |    and associated documentation files (the “Software”), to deal in the Software without restriction,          |
    |    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,      |
    |    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,      |
    |    subject to the following conditions:                                                                       |
    |                                                                                                               |
    |    The above copyright notice and this permission notice shall be included in all copies or substantial       |
    |    portions of the Software.                                                                                  |
    |                                                                                                               |
    |    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT          |
    |    NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.    |
    |    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,    |
    |    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        |
    |    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                                     |
    +---------------------------------------------------------------------------------------------------------------+


    The SAS-ROSET Java API is the official implementation of the SAS-RCS and SAS-RBS encryption algorithms by saaiqSAS.
    This API is thread-safe.

    Usage instructions:
     1. Include this file `SAS_ROSET.java` file in your project.
     2. Modify the package 'com.sas.roset.api' to match your project.
     3. Use it as a regular class in your project.
     Feel free to modify the API and its algorithms as needed.

    Official documentation:
    https://sas-roset.github.io/docs/java_api/java_api.html

     */

    protected static boolean QUICK_PROCESSING = false;
    private static boolean QUICK_PROCESSING_DYN = false;

    private static boolean STOP_PROCESSES = false;

    /*
    The below '_STORE's are used to store extracted keys (key parts) on the memory.
    Multiple keys can be stored on memory even though only one of each kind (Dynamic & Static)
    will be used per process.
     */

    //private static char[][] STORE_DYN_CHARSETS_RCS_16bit = null;
    private static int[][] STORE_DYN_CHARSETS_RCS_32bit = null;
    private static int[][] STORE_DYN_CHARSETS_RBS_32bit = null;
    private static int[][] STORE_DYN_SETTINGS = null;
    private static int[][] STORE_STATIC_KEYS = null;

    // Key ID to (value/array index) maps
    private static int[][] DYN_ID_TO_DYN_INDEXES_MAP = null;  //  DYN_ID_TO_DYN_INDEXES_MAP[ID][0] = RCS_16bit | [ID][1] = RCS_32bit | [ID][2] = RBS_32bit | [ID][4] = Key Length
    private static int[] ST_ID_TO_ST_LENGTH_MAP = null;

    // Next empty index
    private static int dyn_charset_RCS_32bit_next_index = 0;
    private static int dyn_charset_RBS_32bit_next_index = 0;
    private static int dyn_settings_next_index = 0;
    private static int static_keys_next_id = 0;
    private static int dyn_keys_next_id = 0;

    /*
    The '_HM's are used to store a key array as a hashmap in order to reduce search time
    These hashmaps are written to and used when 'quick processing' is set up.
     */
    private static  HashMap<Integer, Integer> DYN_CHARSET_RCS_HM = null;
    private static  HashMap<Integer, Integer> DYN_CHARSET_RBS_HM = null;
    private static  HashMap<Integer, Integer>[] STATIC_KEYS_HM = null;
    private static int[] STATIC_KEYS_HM_INDEXES = null;

    private static final char[] DROS_CHARSET = {' ','!','\"','#','$','%','&','\'','(',')','*','+',',','-','.','/','0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?','@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','[','\\',']','^','_','`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','{','|','}','~'}; //95chars
    private static final int DROS_OMIT_CHAR = 0x0020; // codepoint of a character to not include in DROS encrypted output
    private static final int MAX_DYN_SETTINGS = 10;

    private static final char[][] RGM_BASE_CHARS = {
            {'0', '1', '@'}, // base2
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@'}, //base10
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', '@'}, //base16
            {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '=', '_', '@'} //base64
    };      // '@' added at end of each array to reserve space for separator (serp), which separates two RGM encoded Strings [ rgmFindSeparator() ]




    // -------------------- API Version --------------------
    // If Dynamic key Setting at position [9] == VERSION_IDENTIFIER, then this version of API supports the key

    protected static String getApiVersion() {
        // FUNCTION/USE: returns the current API's version
        return API_VERSION;
    }

    protected static char getApiVersionId() {
        // FUNCTION/USE: returns the current API's version identifier
        return VERSION_IDENTIFIER;
    }

    protected static boolean apiSupportsVesrion(char api_version_id) {
        // FUNCTION/USE: returns whether this API supports the passed 'VERSION_IDENTIFIER' of Dynamic Key.
        // ('VERSION_IDENTIFIER' is the 9th position of the Dynamic Key integer array)
        return api_version_id == VERSION_IDENTIFIER;
    }

    protected static String getApiVersionForId(char api_version_id) {
        // FUNCTION/USE: returns the API version which supports the passed 'VERSION_IDENTIFIER' of Dynamic Key
        // ('VERSION_IDENTIFIER' is the 9th position of the Dynamic Key integer array)

        switch (api_version_id) {
            case '0' -> {return "v0.x.x";} // pre-release
            case '1' -> {return "v1.x.x";}
        }
        return "invalid_version_identifier";
    }



    // -------------------- Stop Flag --------------------
    protected static void stopAllProcesses() {
        /* FUNCTION/USE: Stops all major long-running processes within the API

           Currently, covers:
                > key generation methods
                > key extraction methods

           !!!!! CALL THIS METHOD ONLY WHEN FORCE CLOSING THE APPLICATION. CONTINUING THE USAGE OF
                 API AFTER THIS METHOD IS CALLED MAY LEAD TO UNEXPECTED ERRORS. !!!!!
         */
        STOP_PROCESSES = true;
    }



    // -------------------- Key Store Controls --------------------
    protected static void initializeDynamicKeyStorage(int num_of_keys, int max_key_length, boolean setForRCS32, boolean setForRBS) {
        if (DYN_ID_TO_DYN_INDEXES_MAP == null) {
            DYN_ID_TO_DYN_INDEXES_MAP = new int[num_of_keys][4];
            STORE_DYN_SETTINGS = new int[num_of_keys][10];
            if (setForRCS32) {STORE_DYN_CHARSETS_RCS_32bit = new int[num_of_keys][max_key_length];}
            if (setForRBS) {STORE_DYN_CHARSETS_RBS_32bit = new int[num_of_keys][max_key_length];}
        }
    }

    protected static void initializeStaticKeyStorage(int num_of_keys, int max_key_length) {
        if (STORE_STATIC_KEYS == null) {
            STORE_STATIC_KEYS = new int[num_of_keys][max_key_length];
            ST_ID_TO_ST_LENGTH_MAP = new int[num_of_keys];
        }
    }

    private static void expand_Dyn_Index_Store(int add) {
        if (DYN_ID_TO_DYN_INDEXES_MAP == null) {
            DYN_ID_TO_DYN_INDEXES_MAP = new int[add][4];
        } else {
            int[][] newArr = new int[DYN_ID_TO_DYN_INDEXES_MAP.length+add][4];
            for (int i = 0; i < DYN_ID_TO_DYN_INDEXES_MAP.length; i++) {
                System.arraycopy(DYN_ID_TO_DYN_INDEXES_MAP[i], 0, newArr[i], 0, DYN_ID_TO_DYN_INDEXES_MAP[i].length);
            }
            DYN_ID_TO_DYN_INDEXES_MAP = newArr;
        }
    }
    private static void expand_Dyn_Settings_Store(int add) {
        if (STORE_DYN_SETTINGS == null) {
            STORE_DYN_SETTINGS = new int[add][10];
        } else {
            int[][] newArr = new int[STORE_DYN_SETTINGS.length+add][10];
            for (int i = 0; i < STORE_DYN_SETTINGS.length; i++) {
                System.arraycopy(STORE_DYN_SETTINGS[i], 0, newArr[i], 0, STORE_DYN_SETTINGS[i].length);
            }
            STORE_DYN_SETTINGS = newArr;
        }
    }

    private static void expand_RCS32_Store(int add, int maxLength) {
        if (STORE_DYN_CHARSETS_RCS_32bit == null) {
            STORE_DYN_CHARSETS_RCS_32bit = new int[add][maxLength];
        } else {
            if (STORE_DYN_CHARSETS_RCS_32bit[0].length > maxLength) {
                maxLength = STORE_DYN_CHARSETS_RCS_32bit[0].length;
            }
            int[][] newArr = new int[STORE_DYN_CHARSETS_RCS_32bit.length+add][maxLength];

            for (int i = 0; i < STORE_DYN_CHARSETS_RCS_32bit.length; i++) {
                System.arraycopy(STORE_DYN_CHARSETS_RCS_32bit[i], 0, newArr[i], 0, STORE_DYN_CHARSETS_RCS_32bit[i].length);
            }

            STORE_DYN_CHARSETS_RCS_32bit = newArr;
        }
    }

    private static void expand_RBS_Store(int add, int maxLength) {
        if (STORE_DYN_CHARSETS_RBS_32bit == null) {
            STORE_DYN_CHARSETS_RBS_32bit = new int[add][maxLength];
        } else {
            if (STORE_DYN_CHARSETS_RBS_32bit[0].length > maxLength) {
                maxLength = STORE_DYN_CHARSETS_RBS_32bit[0].length;
            }
            int[][] newArr = new int[STORE_DYN_CHARSETS_RBS_32bit.length+add][maxLength];

            for (int i = 0; i < STORE_DYN_CHARSETS_RBS_32bit.length; i++) {
                System.arraycopy(STORE_DYN_CHARSETS_RBS_32bit[i], 0, newArr[i], 0, STORE_DYN_CHARSETS_RBS_32bit[i].length);
            }

            STORE_DYN_CHARSETS_RBS_32bit = newArr;
        }
    }

    private static void expand_Static_Length_Store(int add) {
        if ( ST_ID_TO_ST_LENGTH_MAP == null) {
            ST_ID_TO_ST_LENGTH_MAP = new int[add];
        } else {
            int[] newArr = new int[ST_ID_TO_ST_LENGTH_MAP.length+add];
            System.arraycopy(ST_ID_TO_ST_LENGTH_MAP, 0, newArr, 0, ST_ID_TO_ST_LENGTH_MAP.length);
            ST_ID_TO_ST_LENGTH_MAP = newArr;
        }
    }

    private static void expand_Static_Store(int add, int maxLength) {
        if (STORE_STATIC_KEYS == null) {
            STORE_STATIC_KEYS = new int[add][maxLength];
        } else {
            if (STORE_STATIC_KEYS[0].length > maxLength) {
                maxLength = STORE_STATIC_KEYS[0].length;
            }
            int[][] newArr = new int[STORE_STATIC_KEYS.length+add][maxLength];

            for (int i = 0; i < STORE_STATIC_KEYS.length; i++) {
                System.arraycopy(STORE_STATIC_KEYS[i], 0, newArr[i], 0, STORE_STATIC_KEYS[i].length);
            }

            STORE_STATIC_KEYS = newArr;
        }
    }

    protected static void resetAllKeyStores() {
        /* FUNCTION/USE: resets all key store variables
                         ( Releases current objects ) */

        STORE_DYN_CHARSETS_RCS_32bit = null;
        STORE_DYN_CHARSETS_RBS_32bit = null;
        STORE_DYN_SETTINGS = null;
        STORE_STATIC_KEYS = null;
        ST_ID_TO_ST_LENGTH_MAP = null;
        DYN_ID_TO_DYN_INDEXES_MAP = null;

        dyn_charset_RCS_32bit_next_index = 0;
        dyn_charset_RBS_32bit_next_index = 0;
        dyn_settings_next_index = 0;
        static_keys_next_id = 0;
        dyn_keys_next_id = 0;

        DYN_CHARSET_RCS_HM = null;
        DYN_CHARSET_RBS_HM = null;
        STATIC_KEYS_HM = null;
        STATIC_KEYS_HM_INDEXES = null;
    }

    private static boolean keyExistRCS32(int ID) {
        // 0 is not an ID, it represents as null
        return DYN_ID_TO_DYN_INDEXES_MAP[ID][0] == 0 && DYN_ID_TO_DYN_INDEXES_MAP[ID][1] > 0;
    }

    private static boolean keyExistRBS(int ID) {
        return DYN_ID_TO_DYN_INDEXES_MAP[ID][2] > 0;
    }

    private static boolean keyExistStatic(int ID) {
        return STORE_STATIC_KEYS.length > ID;
    }
    protected static int getDynamicSetting(int dynId, int pos) {
        /*
            FUNCTION/USE: Returns the value of the Dynamic Key Setting at given position for extracted keys

            'pos':
                    0:  ROS method used
                    1:  Static keys reversing order
                    2:  RGM status for text
                    3:  RGM base
                    4:  Empty
                    5:  Data increase: for every
                    6:  Data increase: add (tenths)
                    7:  Data increase: add (units)
                    8:  Empty
                    9:  Algorithm Version
         */
        if (pos > 9 || pos < 0) {
            throw new RuntimeException("getDynamicSetting() - 'int pos' should be between 0 - 9.");}
        return STORE_DYN_SETTINGS[dynId][pos];
    }

    protected static int[] getStaticKey(int stId) {
        return STORE_STATIC_KEYS[stId];
    }

    protected static boolean dynamicKeyExists(int DynId) {
        // FUNCTION/USE: checks whether a given Dynamic Key ID exists on memory
        return (DynId >= 0 ) && (dyn_charset_RCS_32bit_next_index > DynId);
    }

    private static int getDynamicKeyLength(int DynId) {
        return DYN_ID_TO_DYN_INDEXES_MAP[DynId][3];
    }

    private static String getDynamicKeyCharacter(int DynId, int position) {
        if (keyExistRCS32(DynId)) {
            return new String(Character.toChars(STORE_DYN_CHARSETS_RCS_32bit[DynId][position]));
        }
        return "";
    }



    // -------------------- Key Generation --------------------
    protected static int keyLengthForBits(int bits) {
        /*
           FUNCTION/USE: Returns the key length required to support the specified number of bits.

           This is necessary for generating RBS-supported keys, as RBS requires strict key lengths,
           unlike RCS, which supports any length equal to or greater than 70.
        */

        if (bits > 20 || bits < 7) {
            throw new RuntimeException("key_Length_For() - 'int bits' should be between 7 - 20. ( Only that range is supported by SAS-RBS ) ");}
        return calculatePower(2,bits);
    }

    protected static boolean keyLengthSupportsRBS(int length) {
        // FUNCTION/USE: checks whether the passed Key length supports RBS (Binary) Encryption
        return (length > 0) && ((length & (length - 1)) == 0);
    }

    protected static String generateDynamicKeyString(int key_length, int RGM_Status_For_Text, int RGM_base, int Data_Inc_for_every, int Data_Inc_add, boolean random, boolean output_as_base64) {
        //FUNCTION/USE: Returns a generated Dynamic Key as a String

        if (output_as_base64) { // base64 output
            return "ROSDK:" + intArrayToBase64_Encode(generateDynamicKey(key_length, RGM_Status_For_Text, RGM_base, Data_Inc_for_every, Data_Inc_add, random));
        }

        // non base64 output (may contain supplementary characters)
        StringBuilder generated_key_string = new StringBuilder("ROSDK:");
        int[] generated_key_array = generateDynamicKey(key_length, RGM_Status_For_Text, RGM_base, Data_Inc_for_every, Data_Inc_add, random);

        generated_key_string.append(generated_key_array[0]);        // 1.  ROS method used - max 2
        generated_key_string.append(generated_key_array[1]);        // 2.  Static keys reversing order - max 4
        generated_key_string.append(generated_key_array[2]);        // 3.  RGM status for text - max 3          (non rand)
        generated_key_string.append(generated_key_array[3]);        // 4.  RGM base - max 4                     (non rand)
        generated_key_string.append(generated_key_array[4]);        // 5.  Empty
        generated_key_string.append(generated_key_array[5]);        // 6.  Data increase: for every - max 10    (non rand)
        generated_key_string.append(generated_key_array[6]);        // 7.  Data increase: add (tenths) - max 9  (non rand)
        generated_key_string.append(generated_key_array[7]);        // 8.  Data increase: add (units) - max 9  (non rand)
        generated_key_string.append(generated_key_array[8]);        // 9.  Empty
        generated_key_string.append((char) generated_key_array[9]); // 10. API version id

        generated_key_string.append(new String(generated_key_array,10,generated_key_array.length-10)); // charset

        return generated_key_string.toString();
    }

    protected static int[] generateDynamicKey(int key_length, int RGM_Status_For_Text, int RGM_base, int Data_Inc_for_every, int Data_Inc_add, boolean random) {
        /*
           FUNCTION/USE: Returns a generated Dynamic Key as an int array.

           base_types:      |  RGM_Status:   |
           0: base-2        |  0: disabled   |
           1: base-10       |  1: partial    |
           2: base-16       |  2: full       |
           3: base-64       |

           Data_Inc_for_every & Data_Inc_add:
           These values define a ratio used to increase the data size by adding extra random characters
           from the Dynamic Key charset.

           Example:
             [for_every:add]
             2:4 -> For every 2 chars in the data, add 4 extra chars.
        */


        // input checks
        if (key_length > 1050000 || key_length < 100) {
            throw new RuntimeException("generate_Dynamic_Key() - 'int key_length' should be between 100 - 1,050,000 ");}
        if (RGM_Status_For_Text < 0 || RGM_Status_For_Text > 2) {
            throw new RuntimeException("generate_Dynamic_Key() - 'int RGM_Status_For_Text' should be between 0-2 ");}
        if (RGM_base < 0 || RGM_base > 3) {
            throw new RuntimeException("generate_Dynamic_Key() - 'int RGM_base' should be between 0-3 ");}
        if (Data_Inc_for_every < 0 || Data_Inc_for_every > 9) {
            throw new RuntimeException("generate_Dynamic_Key() - 'int Data_Inc_for_every' should be between 0-9 ");}
        if (Data_Inc_add < 0 || Data_Inc_add > 99) {
            throw new RuntimeException("generate_Dynamic_Key() - 'int Data_Inc_add' should be between 0-99 ");}

        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        int[] generated_key = new int[MAX_DYN_SETTINGS + key_length];


        // setting chars generation
        generated_key[0] = rand.nextInt(2);    // 1.  ROS method used - max 2
        generated_key[1] = rand.nextInt(4);    // 2.  Static keys reversing order - max 4
        generated_key[2] = RGM_Status_For_Text;       // 3.  RGM status for text - max 3          (non rand)
        generated_key[3] = RGM_base;                  // 4.  RGM base - max 4                     (non rand)
        generated_key[4] = 0;                         // 5.  Empty
        generated_key[5] = Data_Inc_for_every;        // 6.  Data increase: for every - max 10    (non rand)
        generated_key[6] = Data_Inc_add / 10;         // 7.  Data increase: add (tenths) - max 9  (non rand)
        generated_key[7] = Data_Inc_add % 10;         // 8.  Data increase: add (units) - max 9  (non rand)
        generated_key[8] = 0;                         // 9.  Empty
        generated_key[9] = VERSION_IDENTIFIER;              // 10. Algorithm version

        // charset generation
        if (!random) {
            // [CHOOSE CHARACTERS ORDERLY AND SHUFFLE]
            int codepoint = 0x0020;

            // populate array with ascending codepoints
            for (int i = MAX_DYN_SETTINGS; i < key_length + MAX_DYN_SETTINGS && !STOP_PROCESSES; ) {
                // total surrogate range: 55296 - 57343 (inclusive)
                if (Character.getType(codepoint) != Character.CONTROL && ( codepoint < 55296 || codepoint > 57343) ) {
                    generated_key[i] = codepoint;
                    i++;
                }
                codepoint++;
            }

            // shuffle_Fisher_Yates
            for (int i = generated_key.length - 1; i > MAX_DYN_SETTINGS && !STOP_PROCESSES; i--) { // shuffle full array except first 10 indexes
                int index = rand.nextInt((i + 1) - MAX_DYN_SETTINGS) + MAX_DYN_SETTINGS;
                int temp = generated_key[i];
                generated_key[i] = generated_key[index];
                generated_key[index] = temp;
            }

            return generated_key;

        } else {
            // [CHOOSE CHARACTERS RANDOMLY] - (generating keys via this method consumes more time, but may add extra security)
            BitSet randomUnicode = new BitSet();

            for (int i = 0; i < key_length && !STOP_PROCESSES; ) {
                int minCP = 0x0020;
                int maxCP = 0x10FFFF;
                int randUTFCodePoint = rand.nextInt((maxCP - minCP) + 1) + minCP;

                if (Character.getType(randUTFCodePoint) != Character.CONTROL && ( randUTFCodePoint < 55296 || randUTFCodePoint > 57343) ) { // Character.isValidCodePoint(randUTFCodePoint) always true due to range
                    if (!randomUnicode.get(randUTFCodePoint)) {
                        randomUnicode.set(randUTFCodePoint);
                        generated_key[MAX_DYN_SETTINGS + i] = randUTFCodePoint;
                        i++;
                    }
                }
            }

            return generated_key;
        }
    }

    protected static String generateStaticKeyString(int key_length) {
        // FUNCTION/USE : Returns a single generated Static Key as String
        return "ROSSK:" + intArrayToBase64_Encode(generateStaticKey(key_length));
    }
    protected static int[] generateStaticKey(int key_length) {
        // FUNCTION/USE : Returns a single generated Static Key as int array
        if (key_length > 1050000 || key_length < 70) {
            throw new RuntimeException("generate_Static_Key() - 'int key_length' should be between 70 - 1,050,000 ");}

        // [SHUFFLE ASCENDING CODEPOINTS ARRAY]
        int[] generated_key = new int[key_length];

        for (int i = 0; i < key_length && !STOP_PROCESSES; i++) { // populate array with ascending ints
            generated_key[i] = i;
        }

        // shuffle_Fisher_Yates
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        for (int i = generated_key.length - 1; i > 0 && !STOP_PROCESSES; i--) { // shuffle whole array
            int index = rand.nextInt(i + 1);
            int temp = generated_key[i];
            generated_key[i] = generated_key[index];
            generated_key[index] = temp;
        }

        return generated_key;
    }



    // -------------------- Key Extraction --------------------
    protected static int extractDynamicKeyString(String DynamicKey, boolean key_as_base64) {
        if (key_as_base64) { // key as base64
            return extractDynamicKey(intArrayToBase64_Decode(DynamicKey.substring(6)));
        }

        // key not as base64
        int cp_count = DynamicKey.codePointCount(0,DynamicKey.length());
        int[] key_array = new int[cp_count -6]; // -6 for "ROSDK:"

        key_array[0] = stringToInt(DynamicKey.charAt(6)+"");  // method
        key_array[1] = stringToInt(DynamicKey.charAt(7)+"");  // Static keys reversing
        key_array[2] = stringToInt(DynamicKey.charAt(8)+"");  // RGM status for text
        key_array[3] = stringToInt(DynamicKey.charAt(9)+"");  // RGM base
        key_array[4] = stringToInt(DynamicKey.charAt(10)+""); // Empty
        key_array[5] = stringToInt(DynamicKey.charAt(11)+""); // data increase: for every
        key_array[6] = stringToInt(DynamicKey.charAt(12)+""); // data increase: add (tenths)
        key_array[7] = stringToInt(DynamicKey.charAt(13)+""); // data increase: add (units)
        key_array[8] = stringToInt(DynamicKey.charAt(14)+""); // Empty
        key_array[9] = DynamicKey.charAt(15);                          // api version id

        int i = 10;
        for (int eCP: DynamicKey.substring(16).codePoints().toArray()) { // charset
            key_array[i] = eCP;
            i++;
        }

        return extractDynamicKey(key_array);
    }

    protected static int extractDynamicKey(int[] DynamicKey) {
        // FUNCTION/USE : Extracts a Dynamic Key onto the STORE to store on memory and returns a reference ID as int
        /*
              DynamicKey[0],   method
              DynamicKey[1],   Static keys reversing
              DynamicKey[2],   RGM status for text
              DynamicKey[3],   RGM base
              DynamicKey[4],   Empty
              DynamicKey[5],   data increase: for every
              DynamicKey[6],   data increase: add (tenths)
              DynamicKey[7],   data increase: add (units)
              DynamicKey[8],   Empty
              DynamicKey[9]    api version id

              If 9999 returned, then an error has occurred while extracting key
              If 9998 returned, then the API does not support the algorithm version in which the key was generated.
              You can get the API version which supports the key by passing the 9th position of the Dynamic Key integer array.
              String supported_version = getApiVersion(DynamicKey[9]);
        */

        if (DynamicKey[9] != VERSION_IDENTIFIER) {
            return 9998; // API does not support the algorithm version in which the key was generated
        }

        if (DynamicKey[0] < 2 && DynamicKey[1] < 4 && DynamicKey[2] < 3 && DynamicKey[3] < 4 && DynamicKey[5] < 10 && DynamicKey[6] < 10 && DynamicKey[7] < 10) {

            int keyLength = DynamicKey.length-MAX_DYN_SETTINGS;

            if (DYN_ID_TO_DYN_INDEXES_MAP == null || DYN_ID_TO_DYN_INDEXES_MAP.length-1 < dyn_keys_next_id) { // expand dyn key index array if no space
                expand_Dyn_Index_Store(1); // expand dyn indexes arr if no space
            }

            // ---------- Extract dynamic key settings ----------
            if (STORE_DYN_SETTINGS == null || STORE_DYN_SETTINGS.length-1 < dyn_settings_next_index) { // expand dyn key settings array if no space
                expand_Dyn_Settings_Store(1); // expand dyn settings arr if no space
            }

            System.arraycopy(DynamicKey, 0, STORE_DYN_SETTINGS[dyn_settings_next_index], 0, 10);
            DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][3] = dyn_settings_next_index+1; // store index on Dyn settings arr for key
            dyn_settings_next_index++;                                      // +1 is added above to reserve 0 to represent null


            // Extract dynamic key charset

            // ----------  Extract for SAS-RCS ----------
            if (STORE_DYN_CHARSETS_RCS_32bit == null || STORE_DYN_CHARSETS_RCS_32bit.length-1 < dyn_charset_RCS_32bit_next_index) {
                expand_RCS32_Store(1,keyLength); // expand dyn key RCS 32bit array if no space
            }

            int index = 0;
            for (int i = MAX_DYN_SETTINGS; i < DynamicKey.length && !STOP_PROCESSES; i++) { // store key in keystore
                STORE_DYN_CHARSETS_RCS_32bit[dyn_charset_RCS_32bit_next_index][index++] = DynamicKey[i];
            }

            DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][1] = dyn_charset_RCS_32bit_next_index+1; // store index on RCS32 arr for key
            dyn_charset_RCS_32bit_next_index++;                                      // +1 is added above to reserve 0 to represent null

            DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][3] = keyLength; // store length of key

            // ----------  Extract for SAS-RBS ----------
            // Here, an ascending int array is shuffled according to Dyn key values, hence Dyn key is translated to support RBS
            if (keyLengthSupportsRBS(keyLength)) {
                int[] sorted_dyn_charset = Arrays.copyOf(STORE_DYN_CHARSETS_RCS_32bit[ DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][1]-1 ], STORE_DYN_CHARSETS_RCS_32bit[ DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][1]-1 ].length); // -1 added because 'next RCS 32bit ID' incremented above
                Arrays.sort(sorted_dyn_charset);

                if (STORE_DYN_CHARSETS_RBS_32bit == null || STORE_DYN_CHARSETS_RBS_32bit.length-1 < dyn_charset_RBS_32bit_next_index) {
                    expand_RBS_Store(1,keyLength); // expand dyn key RBS 32bit array if no space
                }

                for (int i = 0; i < keyLength && !STOP_PROCESSES; i++) {
                    int pos = 0;
                    while (STORE_DYN_CHARSETS_RCS_32bit[ DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][1]-1 ][i] != sorted_dyn_charset[pos]) {
                        pos++;
                    }
                    STORE_DYN_CHARSETS_RBS_32bit[dyn_charset_RBS_32bit_next_index][i] = pos;
                }

                DYN_ID_TO_DYN_INDEXES_MAP[dyn_keys_next_id][2] = dyn_charset_RBS_32bit_next_index+1; // store index on RBS32 arr for key
                dyn_charset_RBS_32bit_next_index++;                                      // +1 is added above to reserve 0 to represent null
            }
            dyn_keys_next_id++;
            return (dyn_keys_next_id-1);

        }
        return 9999; // error
    }

    protected static int extractStaticKeyString(String StaticKey) {
        return extractStaticKey(intArrayToBase64_Decode(StaticKey.substring(6)));
    }

    protected static int extractStaticKey(int[] StaticKey) {
        // FUNCTION/USE : Extracts Static Key onto the STORE to store on memory and returns a reference ID as int

        if (STORE_STATIC_KEYS == null || STORE_STATIC_KEYS.length-1 < static_keys_next_id) {
            expand_Static_Store(1,StaticKey.length); // expand static keys array if no space
            expand_Static_Length_Store(1);           // expand static keys length arr if no space
        }

        for (int i = 0; i < StaticKey.length && !STOP_PROCESSES; i++) {
            STORE_STATIC_KEYS[static_keys_next_id][i] = StaticKey[i];
        }

        ST_ID_TO_ST_LENGTH_MAP[static_keys_next_id] = StaticKey.length;
        static_keys_next_id++;
        return (static_keys_next_id-1);
    }

    protected static int extractStaticKeyReversed(int ID_For_Key_To_Be_Reversed) {
        /*
           FUNCTION/USE: Reverses the given Static Key, extracts it to the STORE for memory storage,
           and returns a reference key as an int.

           The parameter 'int ID_For_Key_To_Be_Reversed' should be the ID of an already extracted Static Key.
        */


        int length = ST_ID_TO_ST_LENGTH_MAP[ID_For_Key_To_Be_Reversed];

        if (STORE_STATIC_KEYS.length-1 < static_keys_next_id) {
            expand_Static_Store(1,length); // expand static keys array if no space
            expand_Static_Length_Store(1); // expand static keys length arr if no space
        }

        for (int i = 0; i < length; i++) {
            STORE_STATIC_KEYS[static_keys_next_id][i] = STORE_STATIC_KEYS[ID_For_Key_To_Be_Reversed][(length-1)-i];
        }

        ST_ID_TO_ST_LENGTH_MAP[static_keys_next_id] = length;
        static_keys_next_id++;
        return (static_keys_next_id-1);
    }



    // -------------------- Setup Quick Processing --------------------
   /*
       Quick Processing speeds up key iteration by converting arrays into hashmaps. This improves processing time
       at the cost of additional memory. It can be set up for a key only after it's extracted to the STORE.

       Quick Processing can only be applied to a single set of keys, typically the ones that will be used (e.g., 1 Dynamic key,
       and multiple Static keys).

       NOTE: If multiple sets of keys are needed during processing, DO NOT use Quick Processing, as it will apply to all data
       once set up and affect all future processing with the keys.
    */

    protected static boolean setQuickProcessingDynOnly(int DynUid) {
        /*
        FUNCTION/USE : Set-ups quick processing for a single Dynamic key

        THIS METHOD IS ONLY TO BE USED IN DEBUGGING AND TESTING THE CODE !!!
         */
        DYN_CHARSET_RCS_HM = new HashMap<>();
        DYN_CHARSET_RBS_HM = new HashMap<>();
        if (dynamicKeyExists(DynUid)) {
            int i;

            for (i = 0; i < getDynamicKeyLength(DynUid);i++) { DYN_CHARSET_RCS_HM.put(STORE_DYN_CHARSETS_RCS_32bit[DynUid][i], i); }
            if  (keyExistRBS(DynUid)) {
                i = 0; for (int eInt : STORE_DYN_CHARSETS_RBS_32bit[DynUid]) { DYN_CHARSET_RBS_HM.put(eInt, i); i++;}
            }

            QUICK_PROCESSING_DYN = true;
            return true;
        }
        return false;
    }

    protected static boolean setQuickProcessing(boolean setupDyn, int DynUid, int[] StIDs) {
        // FUNCTION/USE : Set-ups quick processing for all keys needed for processing (1 Dyn, n Static) for both SAS-RCS and SAS-RBS

        int i;

        // Dynamic Key QP Setup
        if (dynamicKeyExists(DynUid)) {
            if (setupDyn) {
                DYN_CHARSET_RCS_HM = new HashMap<>();
                DYN_CHARSET_RBS_HM = new HashMap<>();

                for (i = 0; i < getDynamicKeyLength(DynUid);i++) { DYN_CHARSET_RCS_HM.put(STORE_DYN_CHARSETS_RCS_32bit[DynUid][i], i);}
                if  (keyExistRBS(DynUid)) {
                    i = 0; for (int eInt : STORE_DYN_CHARSETS_RBS_32bit[DynUid]) { DYN_CHARSET_RBS_HM.put(eInt, i); i++;}
                }
            }
        } else {throw new RuntimeException("setQuickProcessing() - DynUid '"+DynUid+"' Not Found (Check if ID is correct, or whether ID was extracted)");}

        // Static Keys QP Setup
        STATIC_KEYS_HM = new HashMap[StIDs.length];
        STATIC_KEYS_HM_INDEXES = new int[StIDs.length];

        for (int n = 0; n < StIDs.length; n++) {
            if (keyExistStatic(StIDs[n]) && !STOP_PROCESSES) {

                STATIC_KEYS_HM[n] = new HashMap<>();

                i = 0;
                for (int eInt: STORE_STATIC_KEYS[StIDs[n]]) {
                    STATIC_KEYS_HM[n].put(eInt,i);
                    i++;
                }

                STATIC_KEYS_HM_INDEXES[n] = StIDs[n];

            } else {if (keyExistStatic(StIDs[n])) {throw new RuntimeException("setQuickProcessing() - StID '"+StIDs[n]+"' Not Found (Check if ID is correct, or whether ID was extracted)");}}
        }

        QUICK_PROCESSING = true;
        return true;
    }



    // -------------------- Metadata Creation  --------------------
    /*
        The following three methods help create metadata for encrypted data using only a Dynamic Key.
    */

    protected static String drosEncrypt(int DynUid, String data) {
         /*
           FUNCTION/USE: Encrypts an ASCII-based String using only the Dynamic Key with the SAS-DROS
           (Direct Random Object Substitution) Cipher.

           Note: The encrypted output will not include 'DROS_OMIT_CHAR', and its length will match
           the input data length.
        */

        if (getDynamicKeyLength(DynUid) < 128) {throw new RuntimeException("dynamicEncrypt() - key lengths less than 128 are not supported");}

        String[] data_array = stringToCharStringArr(data);
        StringBuilder output = new StringBuilder();
        String dynChar;

        int divideBy = 2;
        if (getDynamicKeyLength(DynUid) <= 200) {
            divideBy = 5;
        }

        for (String eChar: data_array) {
            int posASCII = 0;
            while (posASCII < DROS_CHARSET.length-1 && !eChar.equals(""+DROS_CHARSET[posASCII])) {
                posASCII++;
            }
            if (eChar.equals(""+DROS_CHARSET[posASCII])) {
                dynChar = getCharFromDynamicKey(DynUid, divideBy, posASCII);

                if (dynChar.codePointAt(0) == DROS_OMIT_CHAR) { // omit space
                    output.append(getCharFromDynamicKey(DynUid, divideBy, 97));
                } else {
                    output.append(dynChar);
                }

            } else {
                output.append(eChar);
            }
        }
        return output.toString();
    }

    protected static String drosDecrypt(int DynUid, String data) {
        /* FUNCTION/USE: Decrypts a given DROS cipher text String using Dynamic Key only
         */
        if (getDynamicKeyLength(DynUid) < 128) {throw new RuntimeException("dynamicEncrypt() - key lengths less than 128 are not supported");}

        String[] data_array = stringToCharStringArr(data);
        StringBuilder output = new StringBuilder();
        byte divideBy = 2;
        int length = getDynamicKeyLength(DynUid);

        if (length <= 200) {
            divideBy = 5;
        }
        int divided = length / divideBy;

        if (keyExistRCS32(DynUid)) {

            for (String eChar: data_array) {
                if (eChar.codePointAt(0) == STORE_DYN_CHARSETS_RCS_32bit[DynUid][divided+97]) { // check if encrypted space
                    eChar = new String(Character.toChars(DROS_OMIT_CHAR));
                }
                int posKey = 0;
                while (posKey < length - 1 && eChar.codePointAt(0) != STORE_DYN_CHARSETS_RCS_32bit[DynUid][posKey]) {
                    posKey++;
                }
                if (eChar.codePointAt(0) == STORE_DYN_CHARSETS_RCS_32bit[DynUid][posKey]) {
                    output.append(DROS_CHARSET[posKey - divided]);
                } else {
                    output.append(eChar);
                }

            }

        }
        return output.toString();
    }

    protected static String getCharFromDynamicKey(int DynUid, int divideBy,int add) {
        // FUNCTION/USE: returns the character at a given position from the Dynamic Key
        int position = (getDynamicKeyLength(DynUid) / divideBy ) + add;
        if (position >= getDynamicKeyLength(DynUid)) {
            position = position - getDynamicKeyLength(DynUid);
        }
        return getDynamicKeyCharacter(DynUid,position);
    }

    protected static String getExternalChar(String data) {
        // FUNCTION/USE: returns a character from the Unicode set which is not present in the data provided

        int unicode = 0x0020;
        int i = 0;

        while (i < data.length()) {
            int charCount = Character.charCount(data.codePointAt(i));
            if (data.substring(i, i + charCount).codePointAt(0) == unicode) {
                unicode++;
                i = 0;
            }
            i += charCount;
        }

        return new String(Character.toChars(unicode));
    }



    // -------------------- SAS-RBS (Random Binary Substitution) --------------------
    protected static byte[] rbsByteEncrypt(int DynUid, int[] StIDs, int maxByteBufferSize, byte[] data) {
        int method =                STORE_DYN_SETTINGS[DynUid][0];

        // ------------------------- Data Increase & ROS -------------------------
        byte[] DataIncrease_And_ROS_Passed = rbsDataIncreaseAndRosEncrypt(DynUid, StIDs, method,maxByteBufferSize, data);
        data = null;

        // ------------------------- Shuffle -------------------------
        rbsShuffle(StIDs, false, DataIncrease_And_ROS_Passed);
        return DataIncrease_And_ROS_Passed;
    }

    protected static byte[] rbsByteDecrypt(int DynUid, int[] StIDs, int maxByteBufferSize, byte[] encrypted_data) {
        int method =                STORE_DYN_SETTINGS[DynUid][0];

        // ------------------------- Shuffle -------------------------
        rbsShuffle(StIDs, true, encrypted_data);

        // ------------------------- Data Increase & ROS -------------------------
        return rbsDataIncreaseAndRosDecrypt(DynUid, StIDs, method,maxByteBufferSize, encrypted_data);
    }


    private static byte[] rbsDataIncreaseAndRosEncrypt(int DynUid, int[] StIDs, int method, int maxByteBufferSize, byte[] data) {
        /*
            FUNCTION/USE: DataIncrease + ROS (Encrypt) to the given byte data and returns a byte[]
                          containing encrypted data in 8bit groups.

            Adds extra bits to the given byte[], and divides the bits in the provided
            byte into groups of 'n' bits, then each group is encrypted with ROS, and
            once that is complete, all bits in groups are added back to a byte[] and
            returned.
         */
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        int RBS_ST_Key = 0;

        int dataSize = 8;
        int groupSize = (int) (Math.log(getDynamicKeyLength(DynUid)) / Math.log(2));

        int register = 0;
        int regLength = groupSize - 1;

        int inputDataSize = rbsNumberOfBytesToPass(DynUid,maxByteBufferSize,false);
        int outputDataSize = rbsNumberOfBytesToPass(DynUid,maxByteBufferSize,true);

        int bitsToAdd = (outputDataSize - inputDataSize) * 8;
        int for_every = STORE_DYN_SETTINGS[DynUid][5];
        int add = (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        int crr_fe = -1;
        int crr_add;

        ArrayList<Integer> ROS_output = new ArrayList<>();

        for (byte eByte: data) {
            int crrBit = dataSize - 1;

            while (crrBit > -1) {
                int bit = (eByte >> crrBit) & 0x01;

                if ( (crr_fe < for_every-1) || (bitsToAdd == 0) ) {
                    register += bit << regLength;
                    regLength--;
                    crr_fe++;
                } else {
                    crr_add = 0;
                    while (crr_add < add && bitsToAdd > 0) {
                        register += rand.nextInt(2) << regLength;  // add random bit
                        regLength--;
                        bitsToAdd--;
                        crr_add++;

                        if (regLength < 0) { // handle register if full
                            // ROS
                            if (RBS_ST_Key == StIDs.length) {RBS_ST_Key = 0;}
                            int enc = rbsProcess(DynUid,StIDs,method,false,register,RBS_ST_Key);
                            RBS_ST_Key++;
                            ROS_output.add(enc);
                            register = 0;
                            regLength = groupSize - 1;
                        }
                    }
                    crr_fe = 0;
                    register += bit << regLength;
                    regLength--;
                }
                crrBit--;

                if (regLength < 0) { // handle register if full
                    // ROS
                    if (RBS_ST_Key == StIDs.length) {RBS_ST_Key = 0;}
                    int enc = rbsProcess(DynUid,StIDs,method,false,register,RBS_ST_Key);
                    RBS_ST_Key++;
                    ROS_output.add(enc);
                    register = 0;
                    regLength = groupSize - 1;
                }
            }
        } // end of dealing with all data bits

        while (bitsToAdd > 0) { // add any remaining random bits to add
            register += rand.nextInt(2) << regLength;
            regLength--;
            bitsToAdd--;

            if (regLength < 0) { // handle register if full
                // ROS
                if (RBS_ST_Key == StIDs.length) {RBS_ST_Key = 0;}
                int enc = rbsProcess(DynUid,StIDs,method,false,register,RBS_ST_Key);
                RBS_ST_Key++;
                ROS_output.add(enc);
                register = 0;
                regLength = groupSize - 1;
            }
        }

        ROS_output.add(register); // To deal with the reminder which does not fill a group

        // groups back to 8 bit
        int[] ROS_output_intArray = new int[ROS_output.size()];
        for (int i = 0; i < ROS_output.size(); i++) {
            ROS_output_intArray[i] = ROS_output.get(i);
        }

        return rbsConvertGroupsBackToBytes(groupSize,regLength,ROS_output_intArray);
    }

    private static byte[] rbsDataIncreaseAndRosDecrypt(int DynUid, int[] StIDs, int method, int maxByteBufferSize, byte[] data) {
        /*
            FUNCTION/USE: DataIncrease + ROS (Decrypt) to the given byte data and returns a byte[]
                          containing encrypted data in 8bit groups.

            Divides the given byte[] into corresponding n-bit groups and passed each group
            through ROS Decrypt (For RBS) and then adds all data bits (original bits from
            data and not added ones) and returns the decrypted byte[].
         */
        int RBS_ST_Key = 0;

        int dataSize = 8;
        int groupSize = (int) (Math.log(getDynamicKeyLength(DynUid)) / Math.log(2));

        int register = 0;
        int regLength = groupSize - 1;

        int register2 = 0;
        int regLength2 = 7;

        int inputDataSize = rbsNumberOfBytesToPass(DynUid,maxByteBufferSize,false);
        int outputDataSize = rbsNumberOfBytesToPass(DynUid,maxByteBufferSize,true);

        int addedBits = (outputDataSize - inputDataSize) * 8;
        int dataBits = (data.length * 8) - addedBits;
        int for_every = STORE_DYN_SETTINGS[DynUid][5];
        int add = (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        int crr_fe = 0;
        int crr_add = 0;

        ArrayList<Byte> ROS_output = new ArrayList<>();

        for (byte eByte: data) {
            int crrBit = dataSize - 1;

            while (crrBit > -1) {
                int bit = (eByte >> crrBit) & 0x01;
                crrBit--;

                register += bit << regLength;
                regLength--;

                if (regLength < 0) { // handle register if full
                    // ROS
                    if (RBS_ST_Key == StIDs.length) {RBS_ST_Key = 0;}
                    int dec = rbsProcess(DynUid, StIDs ,method, true, register, RBS_ST_Key);
                    RBS_ST_Key++;
                    register = 0;
                    regLength = groupSize - 1;

                    int crrBit2 = groupSize - 1;
                    while (crrBit2 > -1 && dataBits > 0) {
                        int bit2 = (dec >> crrBit2) & 0x01;
                        crrBit2--;

                        if (crr_fe < for_every || (addedBits == 0)) {
                            register2 += bit2 << regLength2;
                            regLength2--;
                            crr_fe++;
                            dataBits--;

                            if (regLength2 < 0) { // handle register2 if full
                                ROS_output.add((byte) register2);
                                register2 = 0 ;
                                regLength2 = 7;
                            }
                        } else {
                            crr_add++;
                            addedBits--;
                            if (crr_add == add) {
                                crr_add = 0;
                                crr_fe = 0;
                            }
                        }
                    }   // end of: while
                }       // end of: if (regLength < 0)
            }           // end of: while
        }               // end of dealing with all data bits

        // convert ArrayList to byte[]
        byte[] ROS_output_byteArray = new byte[ROS_output.size()];
        for (int i = 0; i < ROS_output.size(); i++) {
            ROS_output_byteArray[i] = ROS_output.get(i);
        }
        return ROS_output_byteArray;
    }

    private static int rbsProcess(int DynUid, int[] StIDs, int method, boolean decryptMode, int groupToProcess, int RBS_ST_Key) {
        /*
         methods:
            0: method 1 ROS
            1: method 2 ROS
         */

        if (groupToProcess > getDynamicKeyLength(DynUid)-1) {
            throw new RuntimeException("rbsProcess() - Unsupported 'int groupToProcess' provided. It should not be less than key length at use.");}

        // toggle 'method' if decryptMode is true - this is because both methods are direct opposites
        if (decryptMode && method == 0) {
            method = 1;
        } else if (decryptMode && method == 1) {
            method = 0;
        }


        switch (method) {
            case 0 -> {
                /*
                ------------------------- method 1 ROS -------------------------
                Steps:
                    1. Find position of groupToProcess within Dynamic Key - dyn_pos
                    2. Find the int in the Static Key at 'dyn_pos' - st_pos
                    3. Return the int in Dynamic Key at the 'st_pos'

                n Static Keys are used in a repeating pattern (eg: '123412341234...'), every time this method is run, 'groupToProcess'
                should be processed with the Static Key according to its position.
                 */

                int dyn_pos = 0;

                if (QUICK_PROCESSING) {
                    dyn_pos = DYN_CHARSET_RBS_HM.get(groupToProcess);  // step 1
                } else { // QUICK_PROCESSING disabled
                    // step 1
                    while (dyn_pos < getDynamicKeyLength(DynUid)-1 && (STORE_DYN_CHARSETS_RBS_32bit[DynUid][dyn_pos] != groupToProcess) ) {
                        dyn_pos++;
                    }
                }

                return STORE_DYN_CHARSETS_RBS_32bit[DynUid][ STORE_STATIC_KEYS[StIDs[RBS_ST_Key]][dyn_pos] ];
            } // end of: case -> 0

            case 1 -> {
                /*
                ------------------------- method 2 ROS -------------------------
                Steps:
                    1. Find position of groupToProcess within Dynamic Key - dyn_pos
                    2. Find the position where 'dyn_pos' int is stored in the Static Key - st_pos
                    3. Return the int at 'st_pos' within Dynamic Key

                n Static Keys are used in a repeating pattern (eg: '123412341234...'), every time this method is run, 'groupToProcess'
                should be processed with the Static Key according to its position.
                 */

                if (QUICK_PROCESSING) {
                    int hm_id = 0;
                    while (hm_id < STATIC_KEYS_HM_INDEXES.length && StIDs[RBS_ST_Key] != STATIC_KEYS_HM_INDEXES[hm_id]) {
                        hm_id++;
                    }

                    int dyn_pos = DYN_CHARSET_RBS_HM.get(groupToProcess);  // step 1
                    int st_pos = STATIC_KEYS_HM[hm_id].get(dyn_pos); // step 2

                    return STORE_DYN_CHARSETS_RBS_32bit[DynUid][st_pos]; // step 3

                } else { // QUICK PROCESSING disabled
                    // step 1
                    int dyn_pos = 0;
                    while (dyn_pos < getDynamicKeyLength(DynUid)-1 && (STORE_DYN_CHARSETS_RBS_32bit[DynUid][dyn_pos] != groupToProcess) ) {
                        dyn_pos++;
                    }

                    // step 2
                    int st_pos = 0;
                    while (st_pos < ST_ID_TO_ST_LENGTH_MAP[StIDs[RBS_ST_Key]]-1 && STORE_STATIC_KEYS[StIDs[RBS_ST_Key]][st_pos] != dyn_pos) {
                        st_pos++;
                    }

                    return STORE_DYN_CHARSETS_RBS_32bit[DynUid][st_pos]; // step 3
                }
            }        // end of: case -> 1
        }           // end of: switch(method)
        return 0;
    }

    private static void rbsShuffle( int[] StIDs, boolean reverse, byte[] data) {
        byte temp;
        if (!reverse) { // encrypt
            int key_v_index = 0;
            int key_h_index = STORE_STATIC_KEYS[StIDs[0]].length / 2;

            for (int i = 0; i < data.length; i++) { // for each data unit
                // get modula from static key
                if (key_v_index == StIDs.length) {
                    key_v_index = 0; key_h_index++;
                    if (key_h_index == STORE_STATIC_KEYS[StIDs[0]].length) {key_h_index = 0;}
                }
                int swap_index = ((STORE_STATIC_KEYS[StIDs[key_v_index]][key_h_index] % data.length) + data.length) % data.length; // modula (fit to range)
                key_v_index++;

                // swap
                temp = data[i];
                data[i] = data[swap_index];
                data[swap_index] = temp;

            }

        } else { // decrypt
            int key_v_index = 0;
            int key_h_index = STORE_STATIC_KEYS[StIDs[0]].length / 2;

            for (int i = 0; i < data.length; i++) { // get last v h index
                if (key_v_index == StIDs.length) {
                    key_v_index = 0;
                    key_h_index++;
                    if (key_h_index == STORE_STATIC_KEYS[StIDs[0]].length) {key_h_index = 0;}
                }
                key_v_index++;
            }
            key_v_index--;

            for (int i = data.length-1; i >= 0; i--) { // for each data unit
                // get modula from static key
                if (key_v_index < 0) {
                    key_v_index = StIDs.length-1; key_h_index--;
                    if (key_h_index < 0) {key_h_index = STORE_STATIC_KEYS[StIDs[0]].length-1;}
                }
                int swap_index = ((STORE_STATIC_KEYS[StIDs[key_v_index]][key_h_index] % data.length) + data.length) % data.length; // modula (fit to range)
                key_v_index--;

                // swap
                temp = data[i];
                data[i] = data[swap_index];
                data[swap_index] = temp;
            }
        }
    }

    private static byte[] rbsConvertGroupsBackToBytes(int dataGroupSize,int reminder, int[] groupedData) {
        // FUNCTION/USE: Converts and array of n-bit groups to an array of 8bit groups (byte[]) and returns it
        int outputGroupSize = 8;
        byte register = 0;
        int regLength = outputGroupSize - 1;

        ArrayList<Byte> output = new ArrayList<>();

        for (int i = 0; i < groupedData.length-1; i++) {
            int crrBit = dataGroupSize-1;
            while (crrBit > -1) {
                int bit = (groupedData[i] >> crrBit) & 0x01;
                register += bit << regLength;
                regLength--;
                crrBit--;
                if (regLength < 0) {
                    output.add(register);
                    register = 0;
                    regLength = outputGroupSize - 1;
                }
            }
        }

        if (dataGroupSize-1 > reminder) {
            int crrBit = dataGroupSize-1;
            while (crrBit > reminder-1) {
                int bit = (groupedData[groupedData.length-1] >> crrBit) & 0x01;
                register += bit << regLength;
                regLength--;
                crrBit--;
                if (regLength < 0) {
                    output.add(register);
                    register = 0;
                    regLength = outputGroupSize - 1;
                }
            }
        }

        byte[] outputByteArray = new byte[output.size()];
        for (int i = 0; i < output.size(); i++) {
            outputByteArray[i] = output.get(i);
        }

        return outputByteArray;
    }

    protected static boolean keySupportsRBS(int DynUid) {
        // FUNCTION/USE: checks whether the passed Dynamic Key supports RBS (Binary) Encryption
        int keyLength = getDynamicKeyLength(DynUid);
        return (keyLength > 0) && ((keyLength & (keyLength - 1)) == 0);
    }

    protected static int rbsNumberOfBytesToPass(int DynUid,int maxByteBufferSize, boolean decryptMode) {
        /*
        FUNCTION/USE: Calculates the length which the input byte[] should be when passing to RBS

           When reading byte data from for instance a file, the data should be read in strict number of bytes.
           This method will give you that number. This number will be different when you are reading a file to
           encrypt it and when you are reading an encrypted file to decrypt it. Hence, make sure to set the
           'boolean decryptMode' parameter accordingly.

           'int maxBufferSize' should represent the byte buffer size

           0 is returned if the maxBufferSize is not enough to store the minimum number of bytes needed
         */
        int multiple = 1; // need to change to fit to a good buffer size
        int minBytes = rbsMinimumBytesToRead(DynUid);

        while (minBytes*multiple < maxByteBufferSize) {
            multiple++;
        }
        multiple--;

        int for_every = STORE_DYN_SETTINGS[DynUid][5];
        int add = (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        int bitsToAdd = 0;

        if (for_every > 0 && add > 0) {
            bitsToAdd = ((minBytes*multiple*8) / for_every) * add;
            while ((bitsToAdd % 8) > 0 || (minBytes*multiple)+(bitsToAdd/8) > maxByteBufferSize) {
                multiple--;
                bitsToAdd = ((minBytes*multiple*8) / for_every) * add;
            }
        }
        if (!decryptMode){return (minBytes*multiple);}
        return (minBytes*multiple)+(bitsToAdd/8);
    }

    private static int rbsMinimumBytesToRead(int DynUid) {
        //  FUNCTION/USE: Calculates the minimum amount of bytes needed to make 'n' bit groups with 8 bit groups.
        if (!keyExistRBS(DynUid) && keyExistRCS32(DynUid)) {
            throw new RuntimeException("RBS_minimumBytesToRead() - Dynamic Key with the ID '"+DynUid+"' does not support the SAS-RBS. (Key only supports SAS-RCS)");
        }
        if (!keyExistRBS(DynUid) && !keyExistRCS32(DynUid)) {
            throw new RuntimeException("RBS_minimumBytesToRead() - Dynamic Key with the ID '"+DynUid+"' NOT FOUND!!!");
        }
        int pow = (int) (Math.log(getDynamicKeyLength(DynUid)) / Math.log(2));
        return  (LCMof(pow,8) / 8);
    }




    // -------------------- SAS-RCS (Random Character Substitution) --------------------
    protected static String rcsTextEncrypt(int DynUid, int[] StIDs, String textData) {
        /*
         methods:
         0: method 1
         1: method 2
         */

        int method =                STORE_DYN_SETTINGS[DynUid][0];
        //  st_rev =                STORE_DYN_SETTINGS[DynUid][1];
        int RGM_status =            STORE_DYN_SETTINGS[DynUid][2];
        int base =                  STORE_DYN_SETTINGS[DynUid][3];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][4];
        int data_inc_for_every =    STORE_DYN_SETTINGS[DynUid][5];
        int data_inc_add =          (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][8];
        //  api_version_id =        STORE_DYN_SETTINGS[DynUid][9];

        //System.out.println("0. ORI_DAT: "+textData+ " ORI_DAT: "); //test

        // ------------------------- RGM pass -------------------------
        int[] RGM_passed;
        switch (RGM_status) {
            case 0 -> RGM_passed = textData.codePoints().toArray();                                             // no RGM
            case 1 -> RGM_passed = rgmTextWrap(base,DynUid,false,textData).codePoints().toArray();    // partial RGM
            case 2 -> RGM_passed = rgmTextWrap(base,DynUid,true,textData).codePoints().toArray();     // full RGM
            default -> RGM_passed = new int[0];
        }
        textData = null;

        //System.out.println("1. RGM_ENC: "+Arrays.toString(RGM_passed)+ " RGM_ENC: "+ RGM_passed.length); //test

        // ------------------------- RCS pass -------------------------
        int[] RCS_Passed = rcsProcess(DynUid,StIDs,method,false,RGM_passed);
        RGM_passed = null;

        //System.out.println("2. RCS_ENC: "+Arrays.toString(RCS_Passed)+ " RCS_ENC: "+ RCS_Passed.length); //test

        // ------------------------- Data Increase -------------------------
        int[] DataIncrease_Passed;
        if (data_inc_for_every != 0 && data_inc_add != 0) {
            DataIncrease_Passed = rcsDataIncrease(DynUid, data_inc_for_every, data_inc_add, false, RCS_Passed);
        } else {
            DataIncrease_Passed = RCS_Passed;
        }
        RCS_Passed = null;

        //System.out.println("3. DAT_ENC: "+Arrays.toString(DataIncrease_Passed)+ " DAT_ENC: "+ DataIncrease_Passed.length); //test

        // ------------------------- Shuffle -------------------------
        rcsShuffle(StIDs, false, DataIncrease_Passed);

        //System.out.println("4. SHU_ENC: "+Arrays.toString(DataIncrease_Passed)+ " SHU_ENC: "+ DataIncrease_Passed.length); //test
        //System.out.println("5. ENC_OUT: "+new String(DataIncrease_Passed,0,DataIncrease_Passed.length)+ " ENC_OUT: "); //test

        return new String(DataIncrease_Passed,0,DataIncrease_Passed.length);
    }

    protected static String rcsTextDecrypt(int DynUid, int[] StIDs, String textData) {
         /*
         methods:
         0: method 1
         1: method 2

         */

        int method =                STORE_DYN_SETTINGS[DynUid][0];
        //  st_rev =                STORE_DYN_SETTINGS[DynUid][1];
        int RGM_status =            STORE_DYN_SETTINGS[DynUid][2];
        int base =                  STORE_DYN_SETTINGS[DynUid][3];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][4];
        int data_inc_for_every =    STORE_DYN_SETTINGS[DynUid][5];
        int data_inc_add =          (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][8];
        //  api_version_id =        STORE_DYN_SETTINGS[DynUid][9];

        //System.out.println("5. ENC_DAT: "+textData+ " ENC_DAT: "); //test

        // ------------------------- Shuffle -------------------------
        int[] Un_Shuffled =  textData.codePoints().toArray();
        //System.out.println("4. ENC_DAC: "+Arrays.toString(Un_Shuffled)+ " ENC_DAT: "+ Un_Shuffled.length); //test

        rcsShuffle(StIDs, true, Un_Shuffled);
        textData = null;

        //System.out.println("3. SHU_DEC: "+Arrays.toString(Un_Shuffled)+ " SHU_DEC: "+ Un_Shuffled.length); //test

        // ------------------------- Data Increase -------------------------
        int[] DataIncrease_Passed;
        if (data_inc_for_every != 0 && data_inc_add != 0) {
            DataIncrease_Passed = rcsDataIncrease(DynUid, data_inc_for_every, data_inc_add, true, Un_Shuffled);
        } else {
            DataIncrease_Passed = Un_Shuffled;
        }
        Un_Shuffled = null;

        //System.out.println("2. DAT_DEC: "+Arrays.toString(DataIncrease_Passed)+ " DAT_DEC: "+ DataIncrease_Passed.length); //test
        // ------------------------- RCS pass -------------------------
        int[] RCS_Passed = rcsProcess(DynUid,StIDs,method,true,DataIncrease_Passed);
        DataIncrease_Passed = null;

        //System.out.println("1. RCS_DEC: "+Arrays.toString(RCS_Passed)+ " RCS_DEC: "+ RCS_Passed.length); //test
        // ------------------------- RGM pass -------------------------
        String RCS_Passed_String = new String(RCS_Passed,0,RCS_Passed.length);

        String RGM_passed;
        switch (RGM_status) {
            case 0 -> RGM_passed = RCS_Passed_String;                                                   // no RGM
            case 1 -> RGM_passed = rgmTextUnwrap(base,DynUid,false, RCS_Passed_String);   // partial RGM
            case 2 -> RGM_passed = rgmTextUnwrap(base,DynUid,true, RCS_Passed_String);    // full RGM
            default -> RGM_passed = "";
        }
        RCS_Passed = null;

        //System.out.println("0. RGM_DEC: "+RGM_passed+ " RGM_DEC: "); //test
        return RGM_passed;
    }

    protected static int rcsNumOfBytesToPass(int DynUid, int desiredMaxOutputLength) {
        /*
        FUNCTION/USE: Calculates the length which the input byte[] should be when passing to RCS_Byte_Encrypt
                      if a desired output String length is to meet.

                      NOTE: This method is not neccessary. Any byte array length can be passed (multiple of 3 for base64)

           'int desiredMaxOutputLength' should represent the desired number of characters for the output String
           from RCS_Byte_Encrypt
         */
        int base =                  STORE_DYN_SETTINGS[DynUid][3];
        int data_inc_for_every =    STORE_DYN_SETTINGS[DynUid][5];
        int data_inc_add =          (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];

        int len = desiredMaxOutputLength;
        if (data_inc_add > 0 && data_inc_for_every > 0) {
            while ((len + (data_inc_add * (len / data_inc_for_every))) > desiredMaxOutputLength) {
                len--;
            }
        }

        int buffer =
                switch (base) {
                    case 0 -> ((len / 8)/3)*3;                  // s2
                    case 1 -> (len/3)*3;                        // s10
                    case 2 -> ((len / 2)/3)*3;                  // s16
                    case 3 -> (int) (((len / (1.3333)))/3)*3;   // s64
                    default -> 63;
                };

        if (buffer < 63){ // 63 is the minimum
            return 63;
        } else {
            return buffer;
        }
    }

    protected static String rcsByteEncrypt(int DynUid, int[] StIDs, byte[] byteData) {
        /*
         FUNCTION/USE: Encrypts provided byte array using SAS-RCS
         methods:
         0: method 1
         1: method 2

         */

        int method =                STORE_DYN_SETTINGS[DynUid][0];
        //  st_rev =                STORE_DYN_SETTINGS[DynUid][1];
        //  RGM_status =            STORE_DYN_SETTINGS[DynUid][2];
        int base =                  STORE_DYN_SETTINGS[DynUid][3];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][4];
        int data_inc_for_every =    STORE_DYN_SETTINGS[DynUid][5];
        int data_inc_add =          (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][8];
        //  api_version_id =        STORE_DYN_SETTINGS[DynUid][9];

        // ------------------------- RGM pass -------------------------
        //int[] RGM_passed = rgmByteWrap(base,DynUid,byteData).codePoints().toArray();
        int[] RGM_passed = rgmEncode(base,byteToBaseString(base,byteData),DynUid).codePoints().toArray();

        byteData = null;

        // ------------------------- RCS pass -------------------------
        int[] RCS_Passed = rcsProcess(DynUid,StIDs,method,false,RGM_passed);
        RGM_passed = null;

        // ------------------------- Data Increase -------------------------
        int[] DataIncrease_Passed;
        if (data_inc_for_every != 0 && data_inc_add != 0) {
            DataIncrease_Passed = rcsDataIncrease(DynUid, data_inc_for_every, data_inc_add, false, RCS_Passed);
        } else {
            DataIncrease_Passed = RCS_Passed;
        }
        RCS_Passed = null;

        // ------------------------- Shuffle -------------------------
        rcsShuffle(StIDs, false, DataIncrease_Passed);

        return new String(DataIncrease_Passed,0,DataIncrease_Passed.length);
    }

    protected static byte[] rcsByteDecrypt(int DynUid, int[] StIDs, String textData) {
         /*
         FUNCTION/USE: Decrypts the given RCS Encrypted ciphertext to byte[]
         methods:     |  shuffle_types:
         0: method 1  |   0: reverse shuffle
         1: method 2  |   1: n,(n+x).. shuffle

         */

        int method =                STORE_DYN_SETTINGS[DynUid][0];
        //  st_rev =                STORE_DYN_SETTINGS[DynUid][1];
        //  RGM_status =            STORE_DYN_SETTINGS[DynUid][2];
        int base =                  STORE_DYN_SETTINGS[DynUid][3];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][4];
        int data_inc_for_every =    STORE_DYN_SETTINGS[DynUid][5];
        int data_inc_add =          (STORE_DYN_SETTINGS[DynUid][6]*10)+STORE_DYN_SETTINGS[DynUid][7];
        //  empty =                 STORE_DYN_SETTINGS[DynUid][8];
        //  api_version_id =        STORE_DYN_SETTINGS[DynUid][9];

        // ------------------------- Shuffle -------------------------
        int[] Un_Shuffled =  textData.codePoints().toArray();
        rcsShuffle(StIDs, true, Un_Shuffled);
        textData = null;

        // ------------------------- Data Increase -------------------------
        int[] DataIncrease_Passed;
        if (data_inc_for_every != 0 && data_inc_add != 0) {
            DataIncrease_Passed = rcsDataIncrease(DynUid, data_inc_for_every, data_inc_add, true, Un_Shuffled);
        } else {
            DataIncrease_Passed = Un_Shuffled;
        }
        Un_Shuffled = null;

        // ------------------------- RCS pass -------------------------
        int[] RCS_Passed = rcsProcess(DynUid,StIDs,method,true, DataIncrease_Passed);
        DataIncrease_Passed = null;

        // ------------------------- RGM pass -------------------------
        //byte[] RGM_passed = rgmByteUnwrap(base, DynUid,  new String(RCS_Passed,0,RCS_Passed.length));
        byte[] RGM_passed = baseStringToByte(base,rgmDecode(base,new String(RCS_Passed,0,RCS_Passed.length),DynUid));
        RCS_Passed = null;

        return RGM_passed;
    }

    private static int[] rcsProcess(int DynUid, int[] StIDs, int method, boolean decryptMode, int[] input) {
        /*
         FUNCTION/USE: Performs ROS Cipher on the characters/codepoints of the input data
         method:
            0: method 1 ROS
            1: method 2 ROS
         */

        // toggle 'method' if decryptMode is true - this is because both methods are direct opposites
        if (decryptMode && method == 0) {
            method = 1;
        } else if (decryptMode && method == 1) {
            method = 0;
        }

        int[] RCS_passed = new int[input.length];

        int s = 0;
        switch (method) {
            case 0 -> {
                /*
                ------------------------- method 1 ROS -------------------------
                Steps:
                    1. Find position of eChar within Dynamic Key - dyn_pos
                    2. Find the int in the Static Key at 'dyn_pos' - st_pos
                    3. Return the char in Dynamic Key at the 'st_pos'

                n Static Keys are used in a repeating pattern (eg: '123412341234...'), every char is processed with the Static Key according
                to its position. During this run, any external chars are kept as it is.

                 */
                if (keyExistRCS32(DynUid)) {
                    for (int i = 0; i < input.length; i++) {
                        if (s == StIDs.length) {s = 0;}

                        if (QUICK_PROCESSING) {
                            try {
                                int dyn_pos = DYN_CHARSET_RCS_HM.get(input[i]);  // step 1
                                RCS_passed[i] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][STORE_STATIC_KEYS[StIDs[s]][dyn_pos]]; // step 2,3
                            } catch (Exception e) {
                                // char is external
                                RCS_passed[i] = input[i];
                            }

                        } else { // QUICK_PROCESSING disabled
                            // step 1
                            int dyn_pos = 0;
                            while (dyn_pos < getDynamicKeyLength(DynUid)-1 && input[i] != STORE_DYN_CHARSETS_RCS_32bit[DynUid][dyn_pos] ) {
                                dyn_pos++;
                            }

                            if ( input[i] == STORE_DYN_CHARSETS_RCS_32bit[DynUid][dyn_pos] ) { // check is char is local
                                RCS_passed[i] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][STORE_STATIC_KEYS[StIDs[s]][dyn_pos]]; // step 2,3
                            } else {
                                // char is external
                                RCS_passed[i] = input[i];
                            }
                        }
                        s++;
                    } // end of: for loop
                }

            } // end of: case -> 0

            case 1 -> {
                /*
                ------------------------- method 2 ROS -------------------------
                Steps:
                    1. Find position of eChar within Dynamic Key - dyn_pos
                    2. Find the position where 'dyn_pos' int is stored in the Static Key - st_pos
                    3. Return the char at 'st_pos' within Dynamic Key

                n Static Keys are used in a repeating pattern (eg: '123412341234...'), every char is processed with the Static Key according
                to its position. During this run, any external chars are kept as it is.

                 */
                if (keyExistRCS32(DynUid)) {
                    for (int i = 0; i < input.length; i++) {
                        if (QUICK_PROCESSING) {
                            if (s == StIDs.length) {s = 0;}

                            int hm_id = 0;
                            while (hm_id < STATIC_KEYS_HM_INDEXES.length && StIDs[s] != STATIC_KEYS_HM_INDEXES[hm_id]) {
                                hm_id++;
                            }

                            try {
                                int dyn_pos = DYN_CHARSET_RCS_HM.get(input[i]);  // step 1
                                int st_pos = STATIC_KEYS_HM[hm_id].get(dyn_pos); // step 2
                                RCS_passed[i] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][st_pos]; // step 3

                            } catch (Exception e) {
                                // char is external
                                RCS_passed[i] = input[i];
                            }
                            s++;

                        } else { // QUICK PROCESSING disabled
                            if (s == StIDs.length) {s = 0;}

                            // step 1
                            int dyn_pos = 0;
                            while (dyn_pos < getDynamicKeyLength(DynUid)-1 && input[i] != STORE_DYN_CHARSETS_RCS_32bit[DynUid][dyn_pos] ) {
                                dyn_pos++;
                            }
                            if (input[i] == STORE_DYN_CHARSETS_RCS_32bit[DynUid][dyn_pos]) {
                                // step 2
                                int st_pos = 0;
                                while (st_pos < ST_ID_TO_ST_LENGTH_MAP[StIDs[s]]-1 && STORE_STATIC_KEYS[StIDs[s]][st_pos] != dyn_pos) {
                                    st_pos++;
                                }
                                RCS_passed[i] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][st_pos]; // step 3
                            } else {
                                // char is external
                                RCS_passed[i] = input[i];
                            }

                            s++;
                        }
                    }    // end of: for loop
                }


            }        // end of: case -> 1
        }           // end of: switch(method)

        return RCS_passed;
    }

    private static int[] rcsDataIncrease(int DynUid, int for_every, int add, boolean reverseMode, int[] input) {
        /*
        FUNCTION/USE: Adds random characters into the given input Data by following a (for_every:add) ratio and
                      returns a output as a String

        For every 'for_every' char, 'add' number of random chars are added.

        Example: for_every = 2, add = 3,
                 input:  ABCDEFGHIJKLMNOP
                 output: AB|||CD|||EF|||GH|||IJ|||KL|||MN|||OP|||
                 (where '|' are random chars)
         */
        if (!keyExistRCS32(DynUid)) {
            throw new RuntimeException("rcsDataIncrease() - Dynamic Key with the ID '"+DynUid+"' NOT FOUND!!!");
        }

        int[] DataIncrease_passed;
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        int cf = 0;
        int ca = 0;

        if (!reverseMode) { //encode
            int out_length = ((input.length/for_every) * add) + input.length;
            int o = 0;
            DataIncrease_passed = new int[out_length];
            for (int i = 0; i < input.length; i++) {
                if (cf == for_every) {
                    cf = 0;
                    ca = 0;
                    while (ca < add) {
                        DataIncrease_passed[o] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][rand.nextInt(getDynamicKeyLength(DynUid))];
                        o++;
                        ca ++;
                    }
                }
                DataIncrease_passed[o] = input[i];
                o++;
                cf++;
            }

            for (;o < out_length; o++) { // fill up any remaining space
                DataIncrease_passed[o] = STORE_DYN_CHARSETS_RCS_32bit[DynUid][rand.nextInt(getDynamicKeyLength(DynUid))];
            }

        } else { // reverse // decode
            int out_length = input.length - ((input.length / (for_every + add)) * add);
            int o = 0;
            DataIncrease_passed = new int[out_length];
            for (int i = 0; i < input.length; i++) {
                if (cf < for_every) {
                    DataIncrease_passed[o] = input[i];
                    o++;
                    cf++;
                } else {
                    ca ++;
                    if (ca == add) {
                        cf = 0;
                        ca = 0;
                    }
                }
            }
        }
        return DataIncrease_passed;
    }

    private static void rcsShuffle( int[] StIDs, boolean reverse, int[] data) {
        int temp;
        if (!reverse) { // encrypt
            int key_v_index = 0;
            int key_h_index = STORE_STATIC_KEYS[StIDs[0]].length / 2;

            for (int i = 0; i < data.length; i++) { // for each data unit
                // get modula from static key
                if (key_v_index == StIDs.length) {
                    key_v_index = 0; key_h_index++;
                    if (key_h_index == STORE_STATIC_KEYS[StIDs[0]].length) {key_h_index = 0;}
                }
                int swap_index = ((STORE_STATIC_KEYS[StIDs[key_v_index]][key_h_index] % data.length) + data.length) % data.length; // modula (fit to range)
                key_v_index++;

                // swap
                temp = data[i];
                data[i] = data[swap_index];
                data[swap_index] = temp;
                //System.out.println(Arrays.toString(data) +" i"+i+" s"+swap_index+" h"+key_h_index+" v"+(key_v_index-1)); // test
            }

        } else { // decrypt
            int key_v_index = 0;
            int key_h_index = STORE_STATIC_KEYS[StIDs[0]].length / 2;

            for (int i = 0; i < data.length; i++) { // get last v h index
                if (key_v_index == StIDs.length) {
                    key_v_index = 0;
                    key_h_index++;
                    if (key_h_index == STORE_STATIC_KEYS[StIDs[0]].length) {key_h_index = 0;}
                }
                key_v_index++;
            }
            key_v_index--;

            for (int i = data.length-1; i >= 0; i--) { // for each data unit
                // get modula from static key
                if (key_v_index < 0) {
                    key_v_index = StIDs.length-1; key_h_index--;
                    if (key_h_index < 0) {key_h_index = STORE_STATIC_KEYS[StIDs[0]].length-1;}
                }
                int swap_index = ((STORE_STATIC_KEYS[StIDs[key_v_index]][key_h_index] % data.length) + data.length) % data.length; // modula (fit to range)
                key_v_index--;

                // swap
                temp = data[i];
                data[i] = data[swap_index];
                data[swap_index] = temp;
                //System.out.println(Arrays.toString(data) +" i"+i+" s"+swap_index+" h"+key_h_index+" v"+(key_v_index+1)); // test
            }
        }
    }


    // ---------- SAS-RGM (Random Group Mapping) ----------
    private static String rgmTextWrap(int base, int DynUid, boolean fullWrap, String data) {
        /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64

            FUNCTION/USE : Encodes a string with RGM and returns the encoded string

            The difference between a full-wrap and partial-wrap is that in partial wrap, only the external chars are
            passed through RGM while keeping local chars as it is. However, in full-wrap all characters in the string
            are passed through RGM character by character. Therefore, boolean parameter 'fullWrap' needs to be set
            accordingly to the needs.
         */
        StringBuilder output = new StringBuilder();
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        String[] serps = rgmFindSeparator(base, DynUid);

        if (!fullWrap) { // partial wrap

            for (String eChar : stringToCharStringArr(data)) {

                // check if char is local or external
                boolean charIsLocal = false;
                if (QUICK_PROCESSING || QUICK_PROCESSING_DYN) {
                    charIsLocal = DYN_CHARSET_RCS_HM.containsKey(eChar.codePointAt(0));
                } else {
                    if (keyExistRCS32(DynUid)) {
                        for (int i = 0; i < getDynamicKeyLength(DynUid); i++) {
                            if (eChar.codePointAt(0) == STORE_DYN_CHARSETS_RCS_32bit[DynUid][i]) {
                                charIsLocal = true;
                                break;
                            }
                        }
                    }
                }

                // check if char is included within serps
                boolean withinSerp = false;
                for (int i = 0; i < serps.length; i++) {
                    if (eChar.equals(serps[i])) {
                        withinSerp = true;
                        break;
                    }
                }

                if (eChar.length() == 1 && charIsLocal && !withinSerp) { // char within BMP, is local, not within serps
                    output.append(eChar);
                } else {  // char out of BMP, not local or within serps
                    output.append(serps[rand.nextInt(serps.length)]); // add random serp from serp array
                    output.append(rgmEncode(base, charToBaseString(base, eChar), DynUid)); // RGM encoded char
                    output.append(serps[rand.nextInt(serps.length)]); // add random serp from serp array
                }
            }

        } else { // full wrap
            for (String eChar : stringToCharStringArr(data)) {
                output.append(rgmEncode(base, charToBaseString(base, eChar), DynUid)); // RGM encoded char
                output.append(serps[rand.nextInt(serps.length)]); // add random serp from serp array
            }
        }

        return output.toString();
    }

    private static String rgmTextUnwrap(int base, int DynUid,boolean fullWrapped, String RGM_wrapped_data) {
        /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64

            FUNCTION/USE : Decodes a RGM encoded string and returns the decoded string
         */
        StringBuilder output = new StringBuilder();
        String[] serps = rgmFindSeparator(base, DynUid);
        StringBuilder RGM_string = new StringBuilder();

        if (!fullWrapped) { // partial unwrap
            boolean serpStarted = false;

            for (String echar : stringToCharStringArr(RGM_wrapped_data)) {
                // check if char is included within serps
                boolean isSerp = false;
                for (int i = 0; i < serps.length; i++) {
                    if (echar.equals(serps[i])) {
                        isSerp = true;
                        break;
                    }
                }
                if (!isSerp) { // not a serp
                    if (serpStarted) {
                        RGM_string.append(echar);
                    } else {
                        output.append(echar);
                    }
                } else {
                    if (serpStarted) {
                        output.append(baseStringToChar(base, rgmDecode(base, RGM_string.toString(), DynUid)));
                        RGM_string.delete(0, RGM_string.length());
                    }
                    serpStarted = !serpStarted;
                }
            }
        } else { // full unwrap
            for (String echar : stringToCharStringArr(RGM_wrapped_data)) {
                // check if char is included within serps
                boolean isSerp = false;
                for (int i = 0; i < serps.length; i++) {
                    if (echar.equals(serps[i])) {
                        isSerp = true;
                        break;
                    }
                }

                if (!isSerp) { // not a serp
                    RGM_string.append(echar);
                } else {
                    output.append(baseStringToChar(base, rgmDecode(base, RGM_string.toString(), DynUid)));
                    RGM_string.delete(0, RGM_string.length());
                }
            }
        }

        return output.toString();
    }

    private static String rgmByteWrap(int base, int DynUid, byte[] bytes) { // binary wrap
          /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64

            FUNCTION/USE : Securely converts byte[] into text via the RGM algorithm and returns String

            When using base64 please provide the bytes in multiples of 3. The last remaining bytes in
            the whole data (eg: file) can be an exception.
         */
        return rgmEncode(base,byteToBaseString(base,bytes),DynUid);
    }

    private static byte[] rgmByteUnwrap(int base, int DynUid, String RGM_wrapped_data) { // binary unwrap
        /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64

            When using this method provide the strings in same length groups as the output from the byte wrap.
            In other words if the byte wrap was carried out for a file in 3 bytes groups, then the output for
            each of those 3 byte groups may be a 4 character string. Hence, you should provide the whole string
            to this method in groups of 4 character strings.
         */
        return  baseStringToByte(base,rgmDecode(base,RGM_wrapped_data,DynUid));
    }

    private static String[] rgmFindSeparator(int base, int DynUid) {
        /*
            FUNCTION/USE: Returns an array of chars which can be used as serps

            The serps are selected via RGM - characters are selected from key via RGM and added to output array

            l = number of base chars in baseX
            k = key length (larger than 'l')
            g = groups of 'l' which can be made from 'k'
            r = remaining chars which don't belong to a group
            p = position reserved for serp in RGM_BASE_CHARS - '@' (last)

            co = current index in output array
            cg = current group
            cr = current remaining
         */
        int l = RGM_BASE_CHARS[base].length;
        int k = getDynamicKeyLength(DynUid);
        int g = k / l;
        int r = k - (g*l);
        //String[] out = new String[g+r]; // used when adding remaining chars (not part of any group) as serps
        String[] out = new String[g];
        int p = l-1;

        int co = 0;
        for (int cg = 0; cg < g; cg++) { // add chars based of RGM
            out[co] = Character.toString( STORE_DYN_CHARSETS_RCS_32bit[DynUid][ p+(l*cg) ] );
            co++;
        }

//        for (int cr = 0; cr < r; cr++) { // add any remaining chars, if any ( starting from end of key to start - right to left )
//            out[co] = Character.toString( STORE_DYN_CHARSETS_RCS_32bit[DynUid][ l - cr -1]); // -1 included to convert 'l' to zero-based indexing
//            co++;
//        } // adding remaining is seen unnecessary, as the serp array gets quite large with longer keys, thus secure

        return out;
    }
    private static String rgmEncode(int base, String baseString, int DynUid) {
        /*
            FUNCTION/USE: Performs RGM on a passed String 'baseString' composed of baseX characters
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        StringBuilder sEncoded = new StringBuilder();
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        int baseLength = RGM_BASE_CHARS[base].length;

        int groups = (getDynamicKeyLength(DynUid) / baseLength);

        for (String echar : stringToCharStringArr(baseString)) {
            int pos = 0;
            while ((pos < baseLength) && (!(RGM_BASE_CHARS[base][pos] + "").equals(echar))) {
                pos++;
            }
            int fin = pos + ( baseLength * rand.nextInt(groups) );
            sEncoded.append(new String(Character.toChars(STORE_DYN_CHARSETS_RCS_32bit[DynUid][fin])));
        }

        return sEncoded.toString();
    }

    private static String rgmDecode(int base, String RGMEncodedString, int DynUid) {
        /*
            FUNCTION/USE: Decodes an RGM encoded String 'RGMEncodedString' back to original String composed of baseX chars
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        StringBuilder sDecoded = new StringBuilder();

        int baseLength = RGM_BASE_CHARS[base].length;

        for (String echar : stringToCharStringArr(RGMEncodedString)) {
            int pos = 0;
            if (QUICK_PROCESSING || QUICK_PROCESSING_DYN) {
                pos = DYN_CHARSET_RCS_HM.get(echar.codePointAt(0));
            } else {
                while (pos < getDynamicKeyLength(DynUid) && echar.codePointAt(0) != STORE_DYN_CHARSETS_RCS_32bit[DynUid][pos]) {
                    pos++;
                }
            }
            int pv = pos-(baseLength*(pos/baseLength));
            sDecoded.append(RGM_BASE_CHARS[base][pv]);
        }

        return sDecoded.toString();
    }

    // ---------- Char/Bin to base 'n' and vice versa converters ----------
    private static String charToBaseString(int base, String strCharacter) {
         /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        String convertedChar = "";
        int codepoint = strCharacter.codePointAt(0);

        switch (base) {
            case 0 -> convertedChar = Integer.toBinaryString(codepoint);
            case 1 -> convertedChar = codepoint+"";
            case 2 -> convertedChar = Integer.toHexString(codepoint);
            case 3 -> {
                byte[] byteArray = new byte[4];

                byteArray[0] = (byte) (codepoint >> 24);
                byteArray[1] = (byte) (codepoint >> 16);
                byteArray[2] = (byte) (codepoint >> 8);
                byteArray[3] = (byte) (codepoint);

                convertedChar = Base64.getEncoder().encodeToString(byteArray).replaceAll("==","_");
                // convert all '==' to single _
            }
        }

        return convertedChar;
    }

    private static String baseStringToChar(int base, String baseString) {
         /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        String convertedChar = "";

        switch (base) {
            case 0 -> convertedChar = new String(Character.toChars(Integer.parseInt(baseString, 2)));
            case 1 -> convertedChar = Character.toString(stringToInt(baseString));
            case 2 -> convertedChar = new String(Character.toChars(Integer.parseInt(baseString, 16)));
            case 3 -> {
                // replace all _ to ==
                byte[] byteArray = Base64.getDecoder().decode(baseString.replaceAll("_","=="));
                int codepoint = ((byteArray[0] & 0xFF) << 24) |
                        ((byteArray[1] & 0xFF) << 16) |
                        ((byteArray[2] & 0xFF) << 8) |
                        (byteArray[3] & 0xFF);
                convertedChar = Character.toString(codepoint);
            }
        }

        return convertedChar;
    }

    private static String byteToBaseString(int base, byte[] bytes) {
            /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        StringBuilder convertedChar = new StringBuilder();
        switch (base) {
            case 0 -> { // base2
                for (byte b : bytes) {
                    for (int i = 7; i >= 0; i--) {
                        int bit = (b >> i) & 1;
                        convertedChar.append(bit);
                    }
                }
            }
            case 1 -> { // base10
                for (int i = 0; i < bytes.length; i++) {

                    int unsignedInt = bytes[i] & 0xFF;

                    if (unsignedInt < 10) { // 0-9
                        convertedChar.append("00").append(unsignedInt);
                    } else if (unsignedInt < 100) { // 10-99
                        convertedChar.append("0").append(unsignedInt);
                    } else {
                        convertedChar.append(unsignedInt);
                    }
                }
            }
            case 2 -> convertedChar.append(HexFormat.of().formatHex(bytes)); // base16
            case 3 -> { // base64
                convertedChar.append( Base64.getEncoder().encodeToString(bytes).replaceAll("==","_") );
            }
        }
        return convertedChar.toString();
    }

    private static byte[] baseStringToByte(int base, String baseString) {
            /*
            base_types:
            0: base-2
            1: base-10
            2: base-16
            3: base-64
         */
        byte[] bytes = new byte[0];

        switch (base) {
            case 0 -> { // base2
                String[] strBytes = stringDivider(baseString,8,true);
                bytes = new byte[strBytes.length];

                for (int i = 0; i < strBytes.length; i++) {
                    bytes[i] = (byte) Integer.parseInt(strBytes[i], 2);
                }
            }
            case 1 -> { // base10
                String[] strDenBytes = stringDivider(baseString,3,true);
                bytes = new byte[strDenBytes.length];

                for (int i = 0; i < strDenBytes.length; i++) {
                    bytes[i] = (byte) stringToInt(strDenBytes[i]);
                }

            }
            case 2 -> { // base16
                bytes = new byte[baseString.length()/2];
                String[] s = stringDivider(baseString,2,true);
                for (int i = 0; i < s.length; i++) {
                    bytes[i] = (byte) HexFormat.fromHexDigits(s[i]);
                }
            }
            case 3 -> { // base64
                // replace all _ to ==
                bytes = Base64.getDecoder().decode( baseString.replaceAll("_","==") );

            }
        }

        return bytes;
    }



    // ---------- Additional Support Methods ----------

    private static int LCMof(int num1, int num2) { // makes use of Euclid's Algorithm
        int divident;
        int divisor;
        int reminder = 1;

        if (num1 > num2) {
            divident = num1;
            divisor = num2;
        } else {
            divident = num2;
            divisor = num1;
        }

        while (reminder != 0) {
            reminder = divident % divisor;
            if (reminder != 0) {
                divident = divisor;
                divisor = reminder;
            }
        }
        return ((num1*num2)/divisor);
    }

    private static int calculatePower(int base, int power) {
        if (power < 0) { throw new IllegalArgumentException("'int power' passed to 'calculatePower() should be greater than 0");}
        int result = 1;
        for (int i = 0; i < power; i++) {
            result *= base;
        }
        return result;
    }

    private static int[] shuffle_Fisher_Yates(int[] arrayToShuffle) {
        SecureRandom rand;
        try {
            rand = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            String os = System.getProperty("os.name").toLowerCase();
            try {
                rand = os.contains("win") ? SecureRandom.getInstance("Windows-PRNG") : SecureRandom.getInstance("NativePRNG");
            } catch (Exception ex) {
                rand = new SecureRandom();
            }
        }

        for (int i = arrayToShuffle.length - 1; i > 0; i--) {
            int index = rand.nextInt(i + 1);
            int temp = arrayToShuffle[i];
            arrayToShuffle[i] = arrayToShuffle[index];
            arrayToShuffle[index] = temp;
        }
        return arrayToShuffle;
    }

    protected static int stringToInt(String stringInt) {
        char[] stringIntArr = stringInt.toCharArray();
        int stringIntLength = stringInt.length()-1;
        StringBuilder revStringInt = new StringBuilder();
        char[] revStringIntArr;
        int tempInt = 0;
        int placeValue = 1;
        int output = 0;

        while (stringIntLength >= 0) {
            revStringInt.append(stringIntArr[stringIntLength]);
            stringIntLength--;
        }

        revStringIntArr = revStringInt.toString().toCharArray();

        for (char echar : revStringIntArr) {
            switch (echar) {
                case ' ', '0' -> tempInt = 0;
                case '1' -> tempInt = 1;
                case '2' -> tempInt = 2;
                case '3' -> tempInt = 3;
                case '4' -> tempInt = 4;
                case '5' -> tempInt = 5;
                case '6' -> tempInt = 6;
                case '7' -> tempInt = 7;
                case '8' -> tempInt = 8;
                case '9' -> tempInt = 9;
            }
            output += tempInt*placeValue;
            placeValue = placeValue*10;
        }
        return output;
    }

    protected static int charToInt(char charInt) {
        int output = 0 ;
        switch (charInt) {
            case '1' -> output = 1;
            case '2' -> output = 2;
            case '3' -> output = 3;
            case '4' -> output = 4;
            case '5' -> output = 5;
            case '6' -> output = 6;
            case '7' -> output = 7;
            case '8' -> output = 8;
            case '9' -> output = 9;
        }

        return output;
    }

    protected static String[] stringBreaker(String stringToBreak, char breakPoint, boolean inputHasBreakPointAtEnd) {
        if (!inputHasBreakPointAtEnd) {
            stringToBreak += breakPoint;
        }
        char[] stringToBreakArr = stringToBreak.toCharArray();
        stringToBreak = ""; stringToBreak = null;

        ArrayList<String> brokenStringArrays = new ArrayList<>();

        StringBuilder piece = new StringBuilder();

        for (char echar: stringToBreakArr) {
            if (echar != breakPoint) {
                piece.append(echar);
            } else {
                brokenStringArrays.add(piece.toString());
                piece = new StringBuilder();
            }
        }

        return brokenStringArrays.toArray(new String[0]);
    }

    protected static String[] stringDivider(String stringToDivide, int eachGroupLength, boolean fitReminderToLength) {

        ArrayList<String> output = new ArrayList<>();
        StringBuilder ts = new StringBuilder();

        for (String eChar: stringToCharStringArr(stringToDivide)) {
            if (ts.codePointCount(0,ts.length()) == eachGroupLength) {
                output.add(ts.toString());
                ts = new StringBuilder();
            }
            ts.append(eChar);
        }

        if (!ts.toString().isEmpty()) {
            if (fitReminderToLength) {
                while (ts.codePointCount(0,ts.length()) < eachGroupLength) {
                    ts.insert(0, "0");
                }
            }
            output.add(ts.toString());
        }

        return output.toArray(new String[0]);
    }

    protected static String[] stringToCharStringArr(String data) {
        List<String> stringList = new ArrayList<>();
        int i = 0;
        while (i < data.length()) {
            int charCount = Character.charCount(data.codePointAt(i));
            stringList.add(data.substring(i, i + charCount));
            i += charCount;
        }
        return stringList.toArray(new String[0]);
    }

    protected static String intArrayToBase64_Encode(int[] array) {
        // Create a byte array of 4 bytes for each int
        byte[] byteArray = new byte[array.length * 4];
        for (int i = 0; i < array.length; i++) {
            byteArray[i * 4] = (byte) (array[i] >> 24);
            byteArray[i * 4 + 1] = (byte) (array[i] >> 16);
            byteArray[i * 4 + 2] = (byte) (array[i] >> 8);
            byteArray[i * 4 + 3] = (byte) (array[i]);
        }

        // Encode the byte array to Base64
        return Base64.getEncoder().encodeToString(byteArray);
    }

    protected static int[] intArrayToBase64_Decode(String base64) {
        // Decode the Base64 string to a byte array
        byte[] byteArray = Base64.getDecoder().decode(base64);

        // Create an int array of the appropriate size
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
