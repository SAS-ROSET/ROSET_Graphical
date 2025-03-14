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
   - Navigate to the `ROSET_Graphical_vX.X.X_MacOS_x86_64` directory using the command:
     
     (Replace `/path/to/` with the actual path, e.g., `Downloads/ROSET_Graphical_vX.X.X_MacOS_x86_64`)

     ```bash
     cd /path/to/ROSET_Graphical_vX.X.X_MacOS_x86_64
     ```

2. Give Execution Permission:
   - Run the following commands in the terminal once you are in the `ROSET_Graphical_vX.X.X_MacOS_x86_64` directory:
     
     [After the first command you may have to enter your login password]

     ```bash
     sudo xattr -rd com.apple.quarantine ../
     chmod -R +x roset.app
     ```
> The commands above will remove the quarantine flag from the program files so that macOS doesn't block it due to being downloaded from the internet, and then give execution permission to `roset.app`

3. Open the Application:
   - Double-click on `roset.app` to open it.

4. Grant Permissions (if prompted):
   - Click Allow or Open if macOS asks for permission.
   - If blocked, go to **System Preferences > Security & Privacy > Open Anyway.**



<br/>
