package sample;

import java.util.*;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Sniffer{// extends Thread{

    private List<PcapIf> allDevicesList = new ArrayList<PcapIf>(); // Will be filled with NICs
    private StringBuilder errorBuffer = new StringBuilder(); // For any error msgs
    ObservableList<String> packetList = FXCollections.observableArrayList();
    private int deviceIndex;
    private PcapIf device;
    private int snaplen = 64 * 1024;           // Capture all packets, no trucation
    private int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
    private int timeout = 10 * 1000;
    public static Ip4 ip = new Ip4();
    public static Ethernet eth = new Ethernet();
    public static Tcp tcp = new Tcp();
    public static Udp udp = new Udp();

    public ObservableList<String> getPacketList() {
        return packetList;
    }

    public List<PcapIf> getAllDevicesList() {
        return allDevicesList;
    }

    public StringBuilder getErrorBuffer() {
        return errorBuffer;
    }

    public int getDeviceIndex() {
        return deviceIndex;
    }

    public void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }

    public void setDevice() {
        this.device = allDevicesList.get(deviceIndex);;
    }

    public void setDevicesList(){
        int r = Pcap.findAllDevs(allDevicesList, errorBuffer);
        if (r == -1 || allDevicesList.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errorBuffer.toString());
            return;
        }
    }

    public ObservableList<String> getObservableListDevicesList(){
        int i = 0;
        ObservableList<String> deviceList= FXCollections.observableArrayList();
        for (PcapIf device : allDevicesList) {
            String description = device.getDescription();
            deviceList.add("#" + i++ + ": " + device.getName() + " " + description);
        }
        return deviceList;
    }

    public void getNextPacket(){

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errorBuffer.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                packet.hasHeader(ip);
                packet.hasHeader(eth);
                Date time = new Date(packet.getCaptureHeader().timestampInMillis());
                int length = packet.getCaptureHeader().caplen();
                System.out.println("new packet: time= " + time + ", new packet: time= " + time + ", Lenght= " + length + ", Source:= " + FormatUtils.ip(ip.source()) + ", Destination:= " + FormatUtils.ip(ip.destination()) + ", IP protocol= " + eth.typeEnum() + ";");

                addPacketToList(time,length);
            }
        };
        pcap.loop(1, jpacketHandler, "");
        pcap.close();
    }

    public void addPacketToList(Date time, int length){
        packetList.add("new packet: time= " + time + ", Length= " + length + ", Source:= " + FormatUtils.ip(ip.source()) + ", Destination:= " + FormatUtils.ip(ip.destination()) + ", IP protocol= " + eth.typeEnum() + ";");
    }

}


