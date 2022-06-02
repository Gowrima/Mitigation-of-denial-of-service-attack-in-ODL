package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;

import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.utils.NetUtils;

/*
 * A five tuple is formed by 
 * 
 * src addr
 * src port
 * dst addr
 * dst port
 * protocol - TCP/UDP
 *
 * 
 * */
public class FourTuple {
	
	public TCP tcp;
	
	public InetAddress src_addr;
	public InetAddress dst_addr;
	public int src_port;
	public int dst_port;
	private boolean SYNrecv;
	private boolean SArecv;
	private boolean ACKrecv;
	private boolean RSTrecv;
	private int flag;
	
	public int getSrcport() {
		return tcp.getSourcePort(); 
	}

	public int getDstport() {
		return tcp.getSourcePort();
	}
	
	public void set_srcport(int sport) {
		this.src_port = sport;
	}
	
	public void set_dstport(int dport) {
		this.dst_port = dport;
	}
	
	public void set_src_addr(InetAddress srcaddr) {
		this.src_addr = srcaddr;
	}
	
	public void set_dst_addr(InetAddress dstaddr) {
		this.dst_addr = dstaddr;
	}
	
	public InetAddress get_srcaddr() {
		return this.src_addr;
	}
	
	public InetAddress get_dstaddr() {
		return this.get_dstaddr();
	}
	
	public void setFlagsHO(int flags) {
			
		if(flags <= 0) {
				return;
		}
			
		if(flags == 2) {
			SYNrecv = true;
		} else if(flags == 16) {
			ACKrecv = true;
		} else if(flags == 4) {
			RSTrecv = true;
		} else if(flags == 12) {
			SArecv = true;
		} else {
			System.out.println("The TCP packet has none of these flags set: SYN, SYN/ACK, RST, ACK");
			return;
		}
			
		return;
	}
	
	public static boolean isHalfOpen(InetAddress host_addr, int flags) {
		// src always sends SYN, dst always sends SA, src should send RST/ACK.
		
		
		return false;
	}
}
