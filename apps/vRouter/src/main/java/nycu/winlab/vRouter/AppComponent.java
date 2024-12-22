/*
 * Copyright 2024-present Open Networking Foundation
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
package nycu.winlab.vRouter;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.ConfigFactory;

import org.onlab.packet.IpAddress;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.onosproject.net.intf.InterfaceService;



import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.ARP;
import org.onlab.packet.Ip6Address;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onosproject.net.Port;
import org.onosproject.net.ConnectPoint;

import org.onosproject.net.intent.*;
import org.onosproject.net.intent.Key;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.ConnectPoint;


import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRuleService;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.Attributes.Name;
import java.nio.ByteBuffer;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {
    private final NameConfigListener cfgListener = new NameConfigListener();
    private final Logger log = LoggerFactory.getLogger(getClass());

    private final ConfigFactory<ApplicationId, NameConfig> factory = new ConfigFactory<ApplicationId, NameConfig>(
        APP_SUBJECT_FACTORY, NameConfig.class, "router") {
        @Override
        public NameConfig createConfig() {
            return new NameConfig();
        }
    };

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private ApplicationId appId;
    private Map<Ip4Address, MacAddress> macTable = new HashMap<>();
    private Boolean BGPintent = false;

    private class NameConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                && event.configClass().equals(NameConfig.class)) {
                NameConfig config = cfgService.getConfig(appId, NameConfig.class);
                if (config != null) {
                    log.info("vrrouting: {}", config.vrrouting());
                }
            }
        }
    }

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.winlab.vRouter");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));
        

        // install a flowrule for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);


        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private void installBGPIntents(NameConfig config) {
        List<String> v4Peers = config.v4Peers();
        List<String> v6Peers = config.v6Peers();
        String devicePort = config.vrrouting();
        DeviceId devID = DeviceId.deviceId(devicePort.split("/")[0]);
        PortNumber port = PortNumber.portNumber(devicePort.split("/")[1]);
        
        for (int i = 0; i < v4Peers.size(); i+=2) {
            Ip4Address peerIP1 = Ip4Address.valueOf(v4Peers.get(i));
            Ip4Address peerIP2 = Ip4Address.valueOf(v4Peers.get(i+1));
            // install flow rule for ARP packets
            TrafficSelector.Builder selector1 = DefaultTrafficSelector.builder();
            selector1.matchIPSrc(peerIP1.toIpPrefix()).matchIPDst(peerIP2.toIpPrefix()).matchEthType(Ethernet.TYPE_IPV4);

            TrafficSelector.Builder selector2 = DefaultTrafficSelector.builder();
            selector2.matchIPSrc(peerIP2.toIpPrefix()).matchIPDst(peerIP1.toIpPrefix()).matchEthType(Ethernet.TYPE_IPV4);
            
            ConnectPoint src = new ConnectPoint(devID, port);
            ConnectPoint dst = interfaceService.getMatchingInterface(IpAddress.valueOf(v4Peers.get(i))).connectPoint();

            log.info("Created intent from {}/{} to {}/{}", src.deviceId(), src.port(), dst.deviceId(), dst.port());

            FilteredConnectPoint fsrc = new FilteredConnectPoint(src);
            FilteredConnectPoint fdst = new FilteredConnectPoint(dst);

            PointToPointIntent intent1 = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of(peerIP1.toString() + "-" + peerIP2.toString(), appId))
                .selector(selector1.build())
                .filteredIngressPoint(fsrc)
                .filteredEgressPoint(fdst)
                .priority(39999)
                .build();

            PointToPointIntent intent2 = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of(peerIP2.toString() + "-" + peerIP1.toString(), appId))
                .selector(selector2.build())
                .filteredIngressPoint(fdst)
                .filteredEgressPoint(fsrc)
                .priority(39999)
                .build();

            intentService.submit(intent1);
            intentService.submit(intent2);
            
        }

        for (int i = 0; i < v6Peers.size(); i+=2) {
            Ip6Address peerIP1 = Ip6Address.valueOf(v6Peers.get(i));
            Ip6Address peerIP2 = Ip6Address.valueOf(v6Peers.get(i+1));
            // install flow rule for ARP packets
            TrafficSelector.Builder selector1 = DefaultTrafficSelector.builder();
            selector1.matchIPv6Src(peerIP1.toIpPrefix()).matchIPv6Dst(peerIP2.toIpPrefix()).matchEthType(Ethernet.TYPE_IPV6);

            TrafficSelector.Builder selector2 = DefaultTrafficSelector.builder();
            selector2.matchIPv6Src(peerIP2.toIpPrefix()).matchIPv6Dst(peerIP1.toIpPrefix()).matchEthType(Ethernet.TYPE_IPV6);
            
            ConnectPoint src = new ConnectPoint(devID, port);
            ConnectPoint dst = interfaceService.getMatchingInterface(IpAddress.valueOf(v6Peers.get(i))).connectPoint();

            log.info("Created intent from {}/{} to {}/{}", src.deviceId(), src.port(), dst.deviceId(), dst.port());

            FilteredConnectPoint fsrc = new FilteredConnectPoint(src);
            FilteredConnectPoint fdst = new FilteredConnectPoint(dst);

            PointToPointIntent intent1 = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of(peerIP1.toString() + "-" + peerIP2.toString(), appId))
                .selector(selector1.build())
                .filteredIngressPoint(fsrc)
                .filteredEgressPoint(fdst)
                .priority(39999)
                .build();

            PointToPointIntent intent2 = PointToPointIntent.builder()
                .appId(appId)
                .key(Key.of(peerIP2.toString() + "-" + peerIP1.toString(), appId))
                .selector(selector2.build())
                .filteredIngressPoint(fdst)
                .filteredEgressPoint(fsrc)
                .priority(39999)
                .build();

            intentService.submit(intent1);
            intentService.submit(intent2);
            
        }
    }

    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            NameConfig config = cfgService.getConfig(appId, NameConfig.class);
            if (!BGPintent && config != null) {

                installBGPIntents(config);
                BGPintent = true;
                log.info("BGP intents installed");
            }


            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            PortNumber recPort = pkt.receivedFrom().port();
            DeviceId devID = pkt.receivedFrom().deviceId();
            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arpPacket = (ARP) ethPkt.getPayload();
            
            // get payload
            Ip4Address srcIp = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
            MacAddress srcMac = MacAddress.valueOf(arpPacket.getSenderHardwareAddress());
            Ip4Address dstIp = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
            MacAddress dstMac = MacAddress.valueOf(arpPacket.getTargetHardwareAddress());

            // rec packet-in from host, create a row for the host
            
            // if it is a request packet
            if (arpPacket.getOpCode() == ARP.OP_REQUEST){

                // write the srcIP if it is not written
                if (macTable.get(srcIp) == null) {
                    macTable.put(srcIp, srcMac);
                    log.info("Add new entry. IP = {}, MAC = {}", srcIp, srcMac);
                }

                if (macTable.get(dstIp) == null){
                    log.info("TABLE MISS. Send request to edge ports");
                    // log.info("table miss devID: {}, src {} / {}, dst: {}, {}", devID, srcIp, srcMac, dstIp, dstMac);
                    flood(ethPkt, devID, recPort);
                } else {
                    log.info("TABLE HIT. Requested MAC = {}", macTable.get(dstIp));
                    // log.info("table hit devID: {}, src {} / {}, dst: {}, {}", devID, srcIp, srcMac, dstIp, dstMac);

                    controller_reply(ethPkt, dstIp, macTable.get(dstIp), devID, recPort);
                }
            }
            else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
                macTable.put(srcIp, srcMac);
                log.info("Add new entry. IP = {}, MAC = {}", srcIp, srcMac);
                // log.info("recv reply devID: {}, src {} / {}, dst: {}, {}", devID, srcIp, srcMac, dstIp, dstMac);

            }

            context.block();

        }
    }

    private void flood(Ethernet ethPkt, DeviceId devID, PortNumber inPort) {
        // all devices
        for (ConnectPoint edgePort : edgePortService.getEdgePoints()) {
            DeviceId outDevID = edgePort.deviceId();
            PortNumber outPort = edgePort.port();
    
            // Check if the current edge port is not the receiving port
            if (!(outDevID.equals(devID) && outPort.equals(inPort))) {
                // send packet to edge ports only
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .setOutput(outPort)
                        .build();
    
                // build and send the outbound packet
                OutboundPacket outboundPacket = new DefaultOutboundPacket(
                        outDevID, treatment, ByteBuffer.wrap(ethPkt.serialize())
                );
                packetService.emit(outboundPacket);
            }
        }
    }

    public void printMap(Map<Ip4Address, MacAddress> map) {
        // Print the entire map using log
        // Loop through the map and print each entry
        for (Map.Entry<Ip4Address, MacAddress> entry : map.entrySet()) {
            log.info("Key: {}, Value: {}", entry.getKey(), entry.getValue());
        }
    }

    private void controller_reply(Ethernet ethPkt, Ip4Address dstIP, MacAddress dstMac,
                                 DeviceId devID, PortNumber outPort) {

        // create Ethernet frame for ARP reply
        Ethernet ethReply = ARP.buildArpReply(dstIP, dstMac, ethPkt);

        // set port
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(outPort)
                .build();
        
        // send to devices
        OutboundPacket outboundPacket = new DefaultOutboundPacket(
                devID,
                treatment,
                ByteBuffer.wrap(ethReply.serialize())
        );
        packetService.emit(outboundPacket);
        
    }

// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

}