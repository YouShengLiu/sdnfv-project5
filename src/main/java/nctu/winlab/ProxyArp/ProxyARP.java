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
import java.nio.ByteBuffer;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;

import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.edge.EdgePortService;

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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    /* Variables */
    private ApplicationId appId;
    private MyPacketProcessor processor = new MyPacketProcessor();
    private Map<Ip4Address, MacAddress> table = new HashMap<>();

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

    private void addTable(Ip4Address ip_addr, MacAddress mac_addr) {
        table.put(ip_addr, mac_addr);
    }

    private MacAddress lookupTable(Ip4Address ip_addr) {
        return table.get(ip_addr);
    }

    private void packetoutEdgePort(InboundPacket packet) {
        ConnectPoint src = packet.receivedFrom();

        for (ConnectPoint cp: edgePortService.getEdgePoints()) {
            if (cp.toString().compareTo(src.toString()) == 0) {
                // log.info("packetout match {} == {}, ignore this port", cp , src);
                continue;
            } else {
                packetService.emit(new DefaultOutboundPacket(
                    cp.deviceId(),
                    DefaultTrafficTreatment.builder().setOutput(cp.port()).build(),
                    packet.unparsed()
                ));
            }
        }
    }

    /* Handle the packets coming from switchs */
    private class MyPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet eth_packet = pkt.parsed();

            if (eth_packet.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp_packet = (ARP) eth_packet.getPayload();
                short op_code = arp_packet.getOpCode();
                
                if (op_code == ARP.OP_REQUEST) {
                    /* ARP Request */
                    Ip4Address src_ip_addr  = Ip4Address.valueOf(arp_packet.getSenderProtocolAddress());
                    Ip4Address dst_ip_addr  = Ip4Address.valueOf(arp_packet.getTargetProtocolAddress());
                    MacAddress src_mac_addr = eth_packet.getSourceMAC();
                    MacAddress dst_mac_addr = lookupTable(dst_ip_addr);

                    if (lookupTable(src_ip_addr) == null) {
                        addTable(src_ip_addr, src_mac_addr);
                    }

                    if (dst_mac_addr == null) {
                        /* Table miss, packet out to all edge ports */
                        log.info("TABLE MISS. Send request to edge ports");

                        packetoutEdgePort(pkt);
                    } else {
                        /* Table hit, generate ARP response to reply the sender */
                        log.info("TABLE HIT. Requested MAC = {}", dst_mac_addr.toString());

                        Ethernet arp_reply = ARP.buildArpReply(dst_ip_addr, dst_mac_addr, eth_packet);

                        packetService.emit(new DefaultOutboundPacket(
                            pkt.receivedFrom().deviceId(),
                            DefaultTrafficTreatment.builder().setOutput(pkt.receivedFrom().port()).build(),
                            ByteBuffer.wrap(arp_reply.serialize())
                        ));
                    }
                } else if (op_code == ARP.OP_REPLY){
                    /* ARP Response */
                    Ip4Address src_ip_addr  = Ip4Address.valueOf(arp_packet.getSenderProtocolAddress());
                    MacAddress src_mac_addr = eth_packet.getSourceMAC();
                    MacAddress dst_mac_addr = eth_packet.getDestinationMAC();

                    if (lookupTable(src_ip_addr) == null) {
                        addTable(src_ip_addr, src_mac_addr);
                    }

                    log.info("RECV REPLY. Requested MAC = {}", dst_mac_addr.toString());
                }
            }
        }
    }
}
