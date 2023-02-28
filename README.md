Introduction

The mitigation technique using IP tables has several loopholes. The IPtable rule drops all the packets after a certain limit, blocking both legitimate and illegitimate traffic. Further, an IPtable rule is a user level mitigation and is not dynamically installed after the attack takes place. It is impossible to add a rule on a host after the attack has happened, because the host could be down and not responsive. The improved mitigation technique acts at the control-plane and dynamically decides about the attacker/genuine host and takes necessary action.

Attack Mitigation Scenarios

Case 1: Host is a regular user and not an attacker
Although we should use experiments to determine a favorable number of TCP connections established by a non-attacker, the experiment can be tuned by changing the value of MAX_TCP_SYN_PACKETS to allow for a non-attacker to never get blacklisted.

Case 2: Host is an attacker
When the host is an attacker, creating TCP connections at the rate greater than rate of MAX_TCP_SYN_PACKETS/sec then the solution will put the host in a blacklist. Subsequent SYN packets from the same host are not sent to the destination and the controller drops the packets.

Implementation

The solution has been implemented on the OpenDaylight controller (Helium) controller and the hosts were simulated on the Mininet VM (2.2.0). The implementation leveraged an existing implementation of switching by installing a flow rule to route packets from a specific source MAC to a destination MAC and source port to a destination port. The reason this implementation was leveraged was swift turnaround and it was not required to write a separate module to do the mitigation.

1. The implementation creates two new threads apart from the running controller thread – “black list task” and “white list task”.
2. The blacklist task wakes up every second and it looks for hosts that have sent more than 10 connections. If found, blacklist task puts the host into Blacklisted Map.
3. The whitelist task wakes up and removes the IP addresses from blacklist periodically. This is to allow only little traffic and not blacklist an IP address forever.

The HashMap with IP address of the source is used as a database for efficient lookups. Further,
only TCP SYN packets are checked for determining the nature of the attack mitigation. Figure 1 shows the controller running. Figure 2 shows the Mininet topology created. Figure 3 shows the IO graph of packet capture done on the victim machine (h2). H1 is the attacking host. In figure 4, the blacklist task is up every second and adds the attacking IP address to blacklist and drops the packets sent by that host. Whitelist task wakes up every 10s to allow the blacklisted traffic, and to ensure that no host is in blacklist forever.
