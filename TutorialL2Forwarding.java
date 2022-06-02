/*
 * Copyright (C) 2014 SDN Hub

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */

/*	CMPE 209 Fall 2014 Extra Project Dr. Younghee Park
 * 
 * Gowrima Kikkkeri Jayaramu SID 008649121
 * 
 * */


package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.lang.String;
import java.util.Map;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.ICMP;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.switchmanager.Subnet;
import java.util.Timer;
import java.util.TimerTask;

public class TutorialL2Forwarding implements IListenDataPacket {
    private static final Logger logger = LoggerFactory
            .getLogger(TutorialL2Forwarding.class);
    private ISwitchManager switchManager = null;
    private IFlowProgrammerService programmer = null;
    private IDataPacketService dataPacketService = null;
    private Map<Long, NodeConnector> mac_to_port = new HashMap<Long, NodeConnector>();
    private String function = "switch";
    private static Map<InetAddress, IPSourcePkt> pktBySrc = new HashMap<InetAddress, IPSourcePkt>();
    private static Map<FourTuple, IPSourcePkt> halfopenpkt = new HashMap<FourTuple, IPSourcePkt>();
    private static final int MAX_SYN_PACKETS_PER_SEC = 10;
    private static final int MAX_ALLOWABLE_SYN_PACKETS_PER_SEC = 15;
    private static final int MAX_HALFOPEN_PACKETS_PER_SEC = 10;
    private static final int BLACKLIST_TIMER_DELAY = 1000;	// perform blacklist task after 1000
    private static final int BLACKLIST_TIMER_PERIOD = 1000;		// perform blacklist task for 1000 period
    private static final int WHITELIST_TIMER_DELAY = 15000;
    private static final int WHITELIST_TIMER_PERIOD = 15000;

    private Timer blackListTimer;
    private Timer whiteListTimer;
    
    class BlackListTask extends TimerTask {
    	public void run() {
    		//System.out.println("Blacklist Task running!");
    		TutorialL2Forwarding.BlackListHashMap();
    	}
    }
    
    class WhiteListTask extends TimerTask {
    	public void run() {
    		//System.out.println("Whitelist Task running!");
    		TutorialL2Forwarding.WhiteListHashMap();
    	}
    }
    
    private synchronized boolean incrementSynCount(InetAddress src) {
    	
    	/* 
    	 * insert source address into the hashmap, if found increment the value by 1
    	 * 
    	 * this function is called for only TCP SYN packet
    	 * 
    	 * objective - find out which source and how many SYN packets
    	 * 
    	 * */
    	// maintain a Map to store the count of SYN packets from an IP address
    	
    	if(src == null) return true;
    	
    	boolean blackListedState = false;
    	
    	if(!pktBySrc.containsKey(src)) {
    		pktBySrc.put(src, new IPSourcePkt(src));
    		//System.out.println("in SYNCOUNT ------> inserting a new ipaddr into the map");
    	} else {
    		Object o = pktBySrc.get(src);
    		IPSourcePkt pktObj = (IPSourcePkt) o;
    		pktObj.incrementPktCount();
       		if(pktBySrc.get(src)!=null) {
    			pktBySrc.put(src, pktObj);
    			//System.out.println("in SYNCOUNT ------> Incrementing the value of the ip addr");
    		}
       		blackListedState = pktObj.isBlackListed();
    	}
    //	System.out.println("\n\t Printing all the entries in hashmap, IP addr and SYN count");
    	// print all the IP addresses and corresponding SYN count
    	for(Map.Entry<InetAddress, IPSourcePkt> entry: pktBySrc.entrySet()) {
    		System.out.println("Host: " + entry.getValue().addr.getHostAddress() + ", Packets: " + entry.getValue().getPacketCount());
    	}
    	return blackListedState;
    }
    
    public synchronized boolean incr_halfOpencount(FourTuple tuple) {
    	
    	/*
    	 * The HashMap contains key, value pair
    	 * Key = tuple
    	 * Value = IPSourcePkt
    	 * increment the half open count only if there is no ACK/RST from a specific IP address
    	 * 
    	 * */
    	if(tuple==null) return true;
    	
    	boolean blackListedState = false;
    	
    	if(!halfopenpkt.containsKey(tuple)) {
    		halfopenpkt.put(tuple, new IPSourcePkt(tuple));
    		//System.out.println("in SYNCOUNT ------> inserting a new ipaddr into the map");
    	} else {
    		Object o = halfopenpkt.get(tuple);  
    		IPSourcePkt pktObj = (IPSourcePkt) o;
    		pktObj.incr_hOpenCount();
       		if(halfopenpkt.get(tuple)!=null) {
    			halfopenpkt.put(tuple, pktObj);
    			//System.out.println("in SYNCOUNT ------> Incrementing the value of the ip addr");
    		}
       		blackListedState = pktObj.isBlackListed();
    	}
    	//	System.out.println("\n\t Printing all the entries in hashmap, IP addr and SYN count");
    	// print all the IP addresses and corresponding SYN count
    	for(Map.Entry<FourTuple, IPSourcePkt> entry: halfopenpkt.entrySet()) {
    		System.out.println("Host: " + entry.getValue().tuple.get_srcaddr() + ", Packets: " + entry.getValue().getHalfOpenCount());
    	}
    	return blackListedState;
    }
    
    
    /*
     * If host is sending more than MAX_SYN_PACKETS_PER_SEC SYN packets he must be an 
     * attacker.
     * 
     * If the host is sending more SYN packets and if there is no ACK/RST packet sent by the host.
     */
    public static synchronized void BlackListHashMap() {
    	//System.out.println("Blacklist Task running");
    	boolean found = false;
    	for(Map.Entry<InetAddress, IPSourcePkt> entry: pktBySrc.entrySet()) {
    		System.out.println(entry.getKey().toString()+" " + entry.getValue().toString());
    		if (entry.getValue().isCountGreaterThan(MAX_SYN_PACKETS_PER_SEC)) {
    			if (entry.getValue().isBlackListed() == false) {
	    			logger.info("Blacklist task detected TCP SYN attack!");
	    			System.out.println("Marking " + entry.getKey().getHostAddress() + " as blacklisted host.");	
	    			entry.getValue().setBlackListed(true);
	    			
    			}
    			found = true;
    		} else {
    			entry.getValue().resetPktCounter();
    		}
    	}
    	
    	for(Map.Entry<FourTuple, IPSourcePkt> entry: halfopenpkt.entrySet()) {
    		System.out.println(entry.getKey().toString()+" "+entry.getValue().toString());
    		if(entry.getValue().getHalfOpenCount()>MAX_HALFOPEN_PACKETS_PER_SEC) {
    			if(entry.getValue().isBlackListedHalfOpen() == false) {
    				logger.info("BlackList task detected TCP HAlf Open Attack!");
    				System.out.println("Marking "+entry.getKey().get_srcaddr() + " as blacklisted host");
    				entry.getValue().setBlackListedHalfOpen(true);
    			}
    			found = true;
    		} else {
    			entry.getValue().resetHalfOpenCounter();
    		}
    	}
    	if (!found) {
    		System.out.println("Blacklist Task finished running");
    	}
    }
    
    
    /* 
     * If host is sending less than MAX_ALLOWABLE_SYN_PACKETS_PER_SEC SYN packets maybe 
     * he is not an attacker and could be a genuine host who's IP address has been spoofed.
     * Give him one more chance to prove that he is not a malicious attacker
     */
    public static synchronized void WhiteListHashMap() {
    	//System.out.println("WhiteList Task running");
    	for(Map.Entry<InetAddress, IPSourcePkt> entry: pktBySrc.entrySet()) {
    		//System.out.println(entry.getKey().toString()+" " + entry.getValue().toString());
    		//if (!entry.getValue().isCountGreaterThan(MAX_ALLOWABLE_SYN_PACKETS_PER_SEC)) {
    			logger.info("Whitelist task reverting host blacklist state(maybe genuine host!)");
    			System.out.println("Marking " + entry.getValue() + " as non-blacklisted host." + 
    					entry.getKey().getHostAddress() + " Host sent " + entry.getValue().getPacketCount() + " packets.");	
    			entry.getValue().setBlackListed(false);
    			entry.getValue().resetPktCounter();
    		//}
    	}
    	System.out.println("Whitelist Task finished running");
    }

    void setDataPacketService(IDataPacketService s) {	
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    public void setFlowProgrammerService(IFlowProgrammerService s)
    {
        this.programmer = s;
    }

    public void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    logger.error("Exception in Bundle uninstall "+bundle.getSymbolicName(), e); 
                }   
            }   
        }   
        blackListTimer = new Timer("CMPE209: BlackList Timer");
        TimerTask foo = new BlackListTask();
        blackListTimer.scheduleAtFixedRate(foo, BLACKLIST_TIMER_DELAY, BLACKLIST_TIMER_PERIOD);

        blackListTimer = new Timer("CMPE209: WhiteList Timer");
        TimerTask bar = new WhiteListTask();
        blackListTimer.scheduleAtFixedRate(bar, WHITELIST_TIMER_DELAY, WHITELIST_TIMER_PERIOD);
 
    }

    /**
     * Function called by the dependency manager when at least one
     * dependency become unsatisfied or when the component is shutting
     * down because for example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called
     * and after the services provided by the class are registered in
     * the service registry
     *
     */
    void start() {
        logger.info("Started");
    }

    /**
     * Function called by the dependency manager before the services
     * exported by the component are unregistered, this will be
     * followed by a "destroy ()" calls
     *
     */
    void stop() {
        logger.info("Stopped");
    }

    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        Set<NodeConnector> nodeConnectors =
                this.switchManager.getUpNodeConnectors(incoming_node);

        for (NodeConnector p : nodeConnectors) {
            if (!p.equals(incoming_connector)) {
                try {
                    RawPacket destPkt = new RawPacket(inPkt);
                    destPkt.setOutgoingNodeConnector(p);
                    this.dataPacketService.transmitDataPacket(destPkt);
                } catch (ConstructionException e2) {
                    continue;
                }
            }
        }
    }

    private int getTCPHeaderLenFlags(String tcpstr)
    {
    	//System.out.println("\n\tGowrima is editing tcp str "+tcpstr);
    	
    	int flag_value = -1;
    	if(!tcpstr.isEmpty()) {
    		String tcpflags = tcpstr.substring(136, 156);
        	String only_flag = tcpflags.substring(16, 20);
        	flag_value = Integer.valueOf(only_flag).intValue();
        	//System.out.println("\t\nTCP Flags "+flag_value);
    	}
    	
    	return flag_value;
    }
    
    private boolean isTCPSyn(int flags)
    {
    	//System.out.println("Inside isTCPflags "+flags);
    	return (flags==2);
    }

    private boolean isTCPACK(int flags) {
    	return (flags==16);
    }
    
    private boolean isTCPRST(int flags) {
    	return (flags==4);
    }
    
    private boolean isTCPSA(int flags) {
    	return (flags==12);
    }
    
    private boolean isHalfOpenPacket(FourTuple tuple, int flags) {
    	
    	return false;
    }
    
    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }

        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();

        // Hub implementation
        if (function.equals("hub")) {
            floodPacket(inPkt);
        } else {
        	Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
            //logger.info(String.valueOf((formattedPak.getHeaderSize())));

            if (formattedPak instanceof Ethernet) {
            	//System.out.println(formattedPak);
            	Object nextPak = formattedPak.getPayload();
            	if (nextPak instanceof IPv4) {
            		IPv4 ipPak = (IPv4)nextPak;
            		//logger.info("Found IP Packet");
            		InetAddress dstaddr = 
            				NetUtils.getInetAddress(ipPak.getDestinationAddress());
            		InetAddress srcaddr = 
            				NetUtils.getInetAddress(ipPak.getSourceAddress());
            		//logger.info("IP packet with dst address" + dstaddr);
            	
            		Object frame = ipPak.getPayload();
            		if (frame instanceof TCP) {
            			
            			TCP tcp = (TCP)frame;
            			String tcpString = tcp.toString();
            			int src_port = tcp.getSourcePort();
            			int dst_port = tcp.getDestinationPort();
            
            			// 	creation of a 4-tuple
            			FourTuple tuple = new FourTuple();
            			tuple.set_src_addr(srcaddr);
            			tuple.set_dst_addr(dstaddr);
            			tuple.set_srcport(src_port);
            			tuple.set_dstport(dst_port);
            			
            			// the tcp packet will contain all 4 elements of a tuple
            			// but only one flag is set based on SYN, SA, ACK or RST
            			
            			
            			int flags = getTCPHeaderLenFlags(tcpString);
            			// checking for half open connections logic should be done here
            			// increment half_Open count only if syn, SA has been obtained between two IP addresses
            			// make use of FourTuple datastructure, FourTuple acts as a filter
            			// since SYN and SA are always sent by attacker and victm, only ACK/RST differentiates genuine traffic
            			//	from attack traffic
            			
            			isHalfOpenPacket(tuple, flags);
            			if(isTCPACK(flags) == false || isTCPRST(flags)==false) {
            				boolean gate = incr_halfOpencount(tuple);
            				if(gate==true) {
            					logger.info("There was no TCP ACK/RST packet sent from "+srcaddr+" has been dropped! (Attack mitigation)");
            					return PacketResult.IGNORED;
            				} else {
            					logger.info("The TCP ACK/RST flag from " + srcaddr + " has been forwarded.");
            				}
            			}
            			
            			/*if (isTCPSyn(flags)==true) {
            			//	logger.info("This is a TCP syn flag from " + srcaddr);
            			
	            			boolean gate = incrementSynCount(srcaddr);
	            			if (gate == true) {
	            				logger.info("The TCP syn flag from " + srcaddr +" has been dropped! (Attack mitigation)");
	            				return PacketResult.IGNORED;
	            			} else {
	            				logger.info("The TCP syn flag from " + srcaddr + " has been forwarded.");
	            			}
            			}
            			*/
            			
            		} else {
            			return PacketResult.IGNORED;
            		}
            	} else {
            		return PacketResult.IGNORED;
            	}
            } else {
            	return PacketResult.IGNORED;
            }
            
              learnSourceMAC(formattedPak, incoming_connector);
            NodeConnector outgoing_connector = 
                knowDestinationMAC(formattedPak);
            if (outgoing_connector == null) {
                floodPacket(inPkt);
            } else {
                if (!programFlow(formattedPak, incoming_connector,
                            outgoing_connector)) {
                    return PacketResult.IGNORED;
                }
                inPkt.setOutgoingNodeConnector(outgoing_connector);
                this.dataPacketService.transmitDataPacket(inPkt);
            }
            
        }
            
        return PacketResult.CONSUME;
    }

    private void learnSourceMAC(Packet formattedPak, NodeConnector incoming_connector) {
        byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        this.mac_to_port.put(srcMAC_val, incoming_connector);
    }

    private NodeConnector knowDestinationMAC(Packet formattedPak) {
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        return this.mac_to_port.get(dstMAC_val) ;
    }

    private boolean programFlow(Packet formattedPak, 
            NodeConnector incoming_connector, 
            NodeConnector outgoing_connector) {
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();

        Match match = new Match();
        match.setField( new MatchField(MatchType.IN_PORT, incoming_connector) );
        match.setField( new MatchField(MatchType.DL_DST, dstMAC.clone()) );

        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(outgoing_connector));

        Flow f = new Flow(match, actions);
        f.setIdleTimeout((short)5);

        // Modify the flow on the network node
        Node incoming_node = incoming_connector.getNode();
        Status status = programmer.addFlow(incoming_node, f);

        if (!status.isSuccess()) {
            logger.warn("SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
        	//logger.info("Flow added");
            return true;
        }
    }
  
}