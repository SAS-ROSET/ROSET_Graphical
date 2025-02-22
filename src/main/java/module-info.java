module com.sas.roset.graphical.roset_graphical {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.desktop;


    opens com.sas.roset.graphical.roset_graphical to javafx.fxml;
    exports com.sas.roset.graphical.roset_graphical;
}