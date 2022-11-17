/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.Map;
import java.lang.String;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.IPv4;

import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;

// import org.onosproject.net.DeviceId;
// import org.onosproject.net.PortNumber;
// import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class ProxyARP {

    private final Logger log = LoggerFactory.getLogger("ProxyARP");


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    /* For registering the application */
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    /* For handling the packet */
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;


    /* Variables */
    private ApplicationId appId;
    private MyPacketProcessor processor = new MyPacketProcessor();
    private Map<String, String> table = new HashMap<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.proxyarp");
        packetService.addProcessor(processor, PacketProcessor.director(2));

        requestPacket();

        log.info("Started {}", appId.id());
    }

    @Deactivate
    protected void deactivate() {

        cancelRequestPacket();

        log.info("Stopped");
    }

    /* Request packet */
    private void requestPacket() {
        // Request for IPv4 packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    /* Cancel request packet */
    private void cancelRequestPacket() {
        // Cancel the request for IPv4 packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    private void addTable(String ip_addr, String mac_addr) {
        table.put(ip_addr, mac_addr);
    }

    private String lookupTable(String ip_addr) {
        return table.get(ip_addr);
    }

    /* Handle the packets coming from switchs */
    private class MyPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                // log.info("Packet has been handled, skip it...");
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet eth_packet = pkt.parsed();
            // IPacket eth_payload = eth_packet.getPayload();

            if (eth_packet.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp_packet = (ARP) eth_packet.getPayload();
                short op_code = arp_packet.getOpCode();
                
                if (op_code == 1) {
                    /* ARP Request */
                    String src_ip_addr  = IPv4.fromIPv4Address(IPv4.toIPv4Address(arp_packet.getSenderProtocolAddress()));
                    String dst_ip_addr  = IPv4.fromIPv4Address(IPv4.toIPv4Address(arp_packet.getTargetProtocolAddress()));
                    String src_mac_addr = eth_packet.getSourceMAC().toString();
                    String dst_mac_addr = lookupTable(dst_ip_addr);

                    if (lookupTable(src_ip_addr) == null) {
                        addTable(src_ip_addr, src_mac_addr);
                    }

                    if (dst_mac_addr == null) {
                        log.info("TABLE MISS. Send request to edge ports");
                    } else {
                        log.info("TABLE HIT. Requested MAC = {}", dst_mac_addr);
                    }

                    log.info("ARP Request: {}", arp_packet);
                    log.info("MAC: {} IP: {}", src_mac_addr, src_ip_addr);
                } else if (op_code == 2){
                    /* ARP Response */
                    log.info("ARP Response: {}", arp_packet);
                }
            }
        }
    }
}
