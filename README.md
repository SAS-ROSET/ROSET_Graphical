<p align="center">
    <img  src="https://sas-roset.github.io/imgs/SAS_ROSET_LOGO_NAME.png"/>
</p>

<p align="center">
    <img src="https://sas-roset.github.io/imgs/SAS-ROSET_GUI_1.png"/>
</p>

# ROS Encryption Tool (ROSET Graphical)

ROS Encryption Tool is a user-friendly encryption application that provides full access to the SAS-RCS and SAS-RBS encryption algorithms. It supports both text and file encryption, including multi-threaded, parallel, multi-point file encryption. Key management is also simplified.

For a more visually appealing and easier-to-navigate experience, visit the [SAS-ROSET official website](https://sas-roset.github.io).

**License: [GNU GPLv3](LICENSE)**

<br/>

## **Documentation and Usage Guide**:
For detailed documentation and usage instructions on how to use the ROS Encryption Tool, visit the [Documentation and Usage Guide](https://sas-roset.github.io/docs/graphical/graphical.html).

<br/>

## Setting up the ROS Encryption Tool:

Go to the latest release and download the archive for your operating system or architecture.  
For a smoother experience, use the [download page](https://sas-roset.github.io/download.html).

> _No dependencies are required to run the ROS Encryption Tool._  
> _The executables are designed to run out of the box, making them portable and easy to use without installation._

<br/>

### Instructions for *Windows*:
1. Extract the `.zip` file
2. To start the tool, open/run the `roset.bat` file
3.  Run the `create_desktop_shortcut.bat` to create a desktop shortcut with icon.

> Note: If you see any prompts preventing you from running the files, click "Run Anyway."
> The SAS-ROSET project is free from any malicious code. We prioritize your security and privacy.

<br/>

### Instructions for *Linux*:
1. Extract the `.zip` file
2. Give execution permission to `roset.sh`:
    ```bash
   chmod +x roset.sh
    ```
4. To run, execute `roset.sh`:
   ```bash
   ./roset.sh
   ```

6. To create desktop shortcut with icon, give execution permission to `create_desktop_shortcut.sh`:
    ```bash
    chmod +x create_desktop_shortcut.sh
    ```

8. To run, execute `create_desktop_shortcut.sh`:
   ```bash
   ./create_desktop_shortcut.sh
   ```

10. To run ROSET, double click on the newly created desktop shortcut.

> Note: If the shortcut doesn't launch, right-click it and select "Allow Launching" or a similar option.

<br/>

### **Instructions for *MacOS***:

1. Open Terminal:
   - If you're already in the directory containing `roset.app` (i.e., inside `ROSET_Graphical_vX.X.X_MacOS_x86_64`), you can directly open Terminal in that directory.
   - Otherwise, open **Terminal** and navigate to the `ROSET_Graphical_vX.X.X_MacOS_x86_64` directory using the `cd` (change directory) command:

     ```bash
     cd /path/to/ROSET_Graphical_vX.X.X_MacOS_x86_64
     ```

     *(Replace `/path/to/ROSET_Graphical_vX.X.X_MacOS_x86_64` with the actual path to the folder.)*

   - If you're unsure of the directory, you can find the full path by running `pwd` (print working directory) in Terminal.
   - Ensure that you're in the same directory as `roset.app` when running commands in step 2.

<br/>

2. Give Execution Permission:
   - Run the following commands while in the `ROSET_Graphical_vX.X.X_MacOS_x86_64` directory to make `roset.app` executable:

     - First, **remove the quarantine attribute** (to bypass macOS security warnings):
       
       ```bash
       sudo xattr -rd com.apple.quarantine ../
       ```

       *(This command removes the quarantine flag from the `roset.app` file and other program files so that macOS doesn't block it due to being downloaded from the internet. Do note that you may need to enter your login password after entering the command above when prompted for `sudo` permissions.)*

     - Then, **grant execute permissions** to the `roset.app` file:

       ```bash
       chmod +x roset.app
       ```

       *(This command ensures the `.app` file has execute permission.)*

<br/>

3. Open the Application:
   - After the above steps, **double-click** on the `roset.app` file to open it.
 
<br/>

4. Grant Permissions (if macOS asks):
   - If macOS displays a message asking for permissions (e.g., "Developer not verified"), click **Allow** or **Open** to grant the necessary permissions.
   - You may also need to go to **System Preferences > Security & Privacy** and click **Open Anyway** if the app is blocked.


<br/>
