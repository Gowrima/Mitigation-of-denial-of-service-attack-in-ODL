package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;

public class IPSourcePkt {
	
	public InetAddress addr;
	private  int pktCount = 0;
	/*private int SYNCount = 0;
	private int SACount = 0;
	private int ACKRSTCount = 0;
	
	*/
	public FourTuple tuple;
	private int half_openCount = 0;
	private boolean isBlackListed;
	private boolean isBlackListedHalfOpen;
	
	
	IPSourcePkt(InetAddress a) {
		addr = a;
		pktCount = 1;
		isBlackListed = false;
	}
	
	IPSourcePkt(FourTuple t) {
		//SAreceived = false;
		//ACKreceived = false;
		half_openCount = 1;
		tuple = t;
		isBlackListedHalfOpen = false;
	}
	
	
	public synchronized void  setBlackListed(boolean state)
	{
		isBlackListed = state;
	}
	
	public synchronized void setBlackListedHalfOpen(boolean state) {
		isBlackListedHalfOpen = state;
	}
	
	public synchronized boolean isBlackListed()
	{
		return isBlackListed;
	}
	
	public synchronized boolean isBlackListedHalfOpen() {
		return isBlackListedHalfOpen;
	}
	
	public synchronized void incrementPktCount () {
		pktCount++;
	}
	
	public synchronized void increment_halfopenCount() {
		half_openCount++;
	}
	
	public synchronized void incr_hOpenCount() {
		half_openCount++;
	}
	
	public synchronized boolean isCountGreaterThan(int value) {
		return (pktCount >= value);
	}
	
	public synchronized void resetPktCounter()
	{
		pktCount = 0;
	}
	
	public synchronized void resetHalfOpenCounter() {
		half_openCount = 0;
	}
	
	public synchronized int getPacketCount() {
		return pktCount;
	}
	
	public synchronized int getHalfOpenCount() {
		return half_openCount;
	}
}