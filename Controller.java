package sample;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;

import java.util.Scanner;

public class Controller extends Thread{

    @FXML
    public ListView<String> devicesList = new ListView<>();

    @FXML
    public ListView<String> packetList = new ListView<>();
    public Label status;

    private ObservableList<String> devicesObservableList = FXCollections.observableArrayList();


    private Sniffer sniffer = new Sniffer();

    public void searchDevices(ActionEvent actionEvent) {
        sniffer.setDevicesList();
        devicesObservableList = sniffer.getObservableListDevicesList();
        //System.out.println(devicesObservableList);
        devicesList.getItems().addAll(devicesObservableList);
        devicesList.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
    }

    public void setSniffer(){
        int index = devicesList.getSelectionModel().getSelectedIndex();
        //System.out.println(index);
        /*if(sniffer.getDeviceIndex()!=index){
            Thread.interrupted();
            clearAll();
        }*/
        sniffer.setDeviceIndex(index);
        sniffer.setDevice();

    }

    public void clearAll(){
        devicesList.getItems().clear();
        packetList.getItems().clear();
        sniffer = null;
    }

    public void startSniffing(ActionEvent actionEvent) {

        status.setText("Seting sniffer");
        setSniffer();
        status.setText("Sniffing packets...");
        packetList.refresh();
        new Thread(() ->
        {
            try
            {
                while (true)
                {
                    sniffer.getNextPacket();
                    packetList.refresh();
                    ObservableList<String> fliesListData = sniffer.getPacketList();
                    Platform.runLater(() ->{ packetList.setItems(fliesListData); });
                    //Thread.sleep(1000);
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }).start();

    }

}