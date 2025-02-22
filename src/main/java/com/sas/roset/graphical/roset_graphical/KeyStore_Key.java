package com.sas.roset.graphical.roset_graphical;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;

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

public class KeyStore_Key {

    private SimpleStringProperty name;
    private SimpleIntegerProperty length;
    private SimpleIntegerProperty st_keys;
    private SimpleStringProperty path;

    public KeyStore_Key(String name, int length, int st_keys, String path) {
        this.name = new SimpleStringProperty(name);
        this.length = new SimpleIntegerProperty(length);
        this.st_keys = new SimpleIntegerProperty(st_keys);
        this.path = new SimpleStringProperty(path);
    }

    public String getName() {
        return name.get();
    }

    public void setName(String name) {
        this.name = new SimpleStringProperty(name);
    }

    public int getLength() {
        return length.get();
    }

    public void setLength(int length) {
        this.length = new SimpleIntegerProperty(length);
    }

    public int getSt_keys() {
        return st_keys.get();
    }

    public void setSt_keys(int st_keys) {
        this.st_keys = new SimpleIntegerProperty(st_keys);
    }

    public String getPath() {
        return path.get();
    }

    public void setPath(String path) {
        this.path = new SimpleStringProperty(path);
    }
}
