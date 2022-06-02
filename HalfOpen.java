package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

public class HalfOpen {

	public FourTuple tuple;
	private boolean SYNrecv;
	private boolean SArecv;
	private boolean ACKrecv;
	private boolean RSTrecv;
	private int flag;
	
	public HalfOpen(FourTuple tuple, int flags) { 
		
		this.tuple = tuple;
		this.flag = flags;
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
	public static boolean isHalfOpen(FourTuple tuple, int flags) {
		
		
		return false;
	}
	
}
