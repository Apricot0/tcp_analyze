## tcp_analyze:
They are 3 files in the folder. 
:------`analysis_pcap_tcp.py`
:------`tcp_test.pcap`
:------`README` 

## README:
The `README` file contains a high-level summary of the `analysis_pcap_tcp code` It includes the instructions on how to run the code.

## PCAP-tcp_test.pcap: 
Packets sent between `130.245.145.12` and `128.208.2.198`. Node `130.245.145.12` establishes the connection (let’s call it sender) with `128.208.2.198` (let’s call is receiver) and then sends data. The trace was captured at the sender.  The pacp file is analyzed by `analysis_pcap_tcp.py`

## Source Code-analysis_pcap_tcp.py:
#### Run
This program doesn't need any extra arguments, since it is designed specifically for `tcp_test.pcap`. This program requires 1 external library: `dpkt`, make sure to install `dpkt` before actually running the process:
```bash
$ pip install dpkt
```

Run `analysis_pcap_tcp.py` using the python interpreter.
```bash
$ python3 analysis_pcap_tcp.py
```

#### Output
Example output should look like:
```

TCP FLOWS INITIALED FROM SENDER (130.245.145.12):

FLOW  1 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
source port:  43498 	source IP address:  130.245.145.12 	destination port:  80 	destination IP address:  128.208.2.198
	* first two transaction (sender -> receiver) after setup: 
		Sequence number:  705669103 Ack number:  1921750144 Receive Window size:  3
		Sequence number:  705669127 Ack number:  1921750144 Receive Window size:  3
	* congestion window sizes estimation:
		window#0:  13
		window#1:  19
		window#2:  40
	* total retransmission: 4
		due to triple duplicate: 2
		possibly due to timeout: 1
		special: 1
	* throughout:  5.133395748425832  Mbps

FLOW  2 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
source port:  43500 	source IP address:  130.245.145.12 	destination port:  80 	destination IP address:  128.208.2.198
	* first two transaction (sender -> receiver) after setup: 
		Sequence number:  3636173852 Ack number:  2335809728 Receive Window size:  3
		Sequence number:  3636173876 Ack number:  2335809728 Receive Window size:  3
	* congestion window sizes estimation:
		window#0:  11
		window#1:  21
		window#2:  32
	* total retransmission: 95
		due to triple duplicate: 4
		possibly due to timeout: 90
		special: 1
	* throughout:  1.2565383572691982  Mbps

FLOW  3 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
source port:  43502 	source IP address:  130.245.145.12 	destination port:  80 	destination IP address:  128.208.2.198
	* first two transaction (sender -> receiver) after setup: 
		Sequence number:  2558634630 Ack number:  3429921723 Receive Window size:  3
		Sequence number:  2558634654 Ack number:  3429921723 Receive Window size:  3
	* congestion window sizes estimation:
		window#0:  19
		window#1:  41
		window#2:  40
	* total retransmission: 1
		due to triple duplicate: 0
		possibly due to timeout: 0
		special: 1
	* throughout:  1.4480242286783183  Mbps

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
TOTAL NUMBER:  3

```

#### High-level Summary
The function `analysis_pcap_tcp` takes in a filename as an argument and analyzes the TCP traffic in the PCAP file specified by the filename. The function uses the `dpkt` library to parse the packets in the PCAP file.

The function creates two dictionaries, `flows_forward` and `flows_backward`, to keep track of the TCP flows in both directions. For each packet in the PCAP file, the function checks if it is an IP packet and a TCP packet. It then identifies the TCP flow by looking at the source and destination IP addresses and port numbers.

The function updates the flow dictionary for each flow based on the flags in the TCP header. If the packet contains the SYN flag and not the ACK flag, the function adds the flow to the `flows_forward` dictionary with a `start time` and an empty list of transactions, also update the `total bytes`. If the packet contains both SYN and ACK flags, the function updates the corresponding flow in the `flows_forward` dictionary with an estimated round-trip time (RTT) and retransmission timeout (RTO) and adds the flow to the `flows_backward` dictionary with an empty list of transactions. The estimated round-trip time (RTT) is estimated by using: the time in the packet contains both SYN and ACK flags(first reception) - the time in the packet only contains the SYN flag (first send), retransmission timeout (RTO) is estimated by calculating $2\times RTT$.

If the packet only contains the ACK flag, then for each packet, record their Seq and Ack numbers, length (excluding header length, but note that it is not used to calculate throughput, just for reference), timestamp, receive window size, and add to the `transactions` list of the corresponding flow. If it is forward direction (from sender to receiver) updates the `total bytes` of the corresponding forward flow using `len(tcp)` (this one includes the header length, based on my understanding we should include heading length when calculate throughout)

After reorder the `transactions` list based on timestamp, we can find the latest transaction from sender to receiver by finding the packet that has max timestamp in the `transactions` list, and set it as `end time` . We can also find the first two transaction from sender to receiver by check the first two transaction in the ordered `transactions` list.  The total amount of bytes is the value of `total bytes` accumulated from the SYN only packet to the last ACK packet, it includes the header length of each packet. The period is `end time`-`start time`. `end time` is the time of the last ACK packet, and `start time` is the time of SYN packet as explained before.  $throughout = total bytes/(endtime - starttime)$. It is displayed in units of Mbps.

The first 3 congestion window sizes are estimated based on the estimated RTT. Use the estimated RTT explained above to measure how many packets are sent in one RTT time. The first time period is from `start time` to `start time` + `RTT` . Check the `transactions` list to see how many packets are in the period and record. The second time period is from `start time + RTT` to `start time + 2RTT`, and so on. 

The number of times a retransmission occurred can be detected by checking the Seq number in forward flow (sender to receiver) transactions, if a Seq number detected more than once then it should be a retransmission. Collect these retransmissions as a new list and examine them one by one. For each retransmission, get the timestamp of the retransmission and check how many transactions in the backward flow (receiver to sender) has the same Ack number as the Seq number of the retransmission before the time of the retransmission (basically check how many duplicates ACK before the retransmission). If the number of duplicates ACK is more then 3, then the retransmission may due to triple duplicate ack. For other retransmissions, filter them again by checking the time difference between the retransmission and the packet that has the same Seq number before. Compare the time difference with the estimate RTO explained before, if the time difference is bigger then the estimate RTO, then the retransmission may due to timeout. The retransmission left may due to special reason.
