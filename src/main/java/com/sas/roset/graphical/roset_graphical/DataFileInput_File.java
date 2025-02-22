package com.sas.roset.graphical.roset_graphical;

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

public class DataFileInput_File {

    private final SimpleStringProperty ID;
    private final SimpleStringProperty type;
    private final SimpleStringProperty path;
    private final SimpleStringProperty name;

    public DataFileInput_File(String ID, String type, String name, String path) {
        this.ID = new SimpleStringProperty(ID);
        this.type = new SimpleStringProperty(type);
        this.path = new SimpleStringProperty(path);
        this.name = new SimpleStringProperty(name);
    }

    public String getID() {
        return ID.get();
    }

    public String getType() {
        return type.get();
    }

    public String getName() {
        return name.get();
    }

    public String getPath() {
        return path.get();
    }

}
