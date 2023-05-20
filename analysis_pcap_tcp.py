import dpkt
import socket


def analysis_pcap_tcp(filename):
    # Open the PCAP file and parse packets
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        flows_forward = {}
        flows_backward = {}
        for ts, buf in pcap:
            # Parse the packet
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                # Ignore non-IP packets
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                # Ignore non-TCP packets
                continue
            tcp = ip.data

            # Identify the TCP flow
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            flow = (src_ip, tcp.sport, dst_ip, tcp.dport)
            reflow = (dst_ip, tcp.dport, src_ip, tcp.sport)

            # Update the flow dictionary
            if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                flows_forward[flow] = {'start_time': ts, 'transactions': [], 'total bytes': len(tcp)}
            if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                if reflow in flows_forward:
                    # use SYN, SYN/ACK estimate rtt
                    flows_forward[reflow]['rtt'] = ts - flows_forward[reflow]['start_time']
                    flows_forward[reflow]['rto'] = 2 * flows_forward[reflow]['rtt']
                    flows_backward[flow] = {'transactions': []}
            elif tcp.flags & dpkt.tcp.TH_FIN:
                if flow in flows_forward:
                    flows_forward[flow]['total bytes'] += len(tcp)
                    flows_forward[flow]['fin_time'] = ts
            elif tcp.flags & dpkt.tcp.TH_ACK:
                if flow in flows_forward:
                    flows_forward[flow]['total bytes'] += len(tcp)
                    flows_forward[flow]['transactions'].append({'seq': tcp.seq, 'ack': tcp.ack,
                                                                'win': tcp.win, 'time': ts,
                                                                'len': len(tcp) - tcp.off * 4})
                if flow in flows_backward:
                    flows_backward[flow]['transactions'].append({'seq': tcp.seq, 'ack': tcp.ack,
                                                                 'win': tcp.win, 'time': ts,
                                                                 'len': len(tcp) - tcp.off * 4})
        for flow in flows_forward:
            flows_forward[flow]['end_time'] = max(flows_forward[flow]['transactions'], key=lambda x: x['time'])['time']
            flows_forward[flow]['transactions'] = sorted(flows_forward[flow]['transactions'], key=lambda x: x['time'])
        for flow in flows_backward:
            flows_backward[flow]['transactions'] = sorted(flows_backward[flow]['transactions'], key=lambda x: x['time'])
        print()
        print("TCP FLOWS INITIALED FROM SENDER (130.245.145.12):\n")
        sender_tcp_counter = 0
        for ith, flow in enumerate(flows_forward):
            if flow[0] == '130.245.145.12':
                sender_tcp_counter = sender_tcp_counter + 1
                print("FLOW ", ith+1, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print("source port: ", flow[1], "\tsource IP address: ", flow[0],
                      "\tdestination port: ", flow[3], "\tdestination IP address: ", flow[2])
                print("\t* first two transaction (sender -> receiver) after setup: ")
                tran2 = flows_forward[flow]['transactions'][1]
                tran3 = flows_forward[flow]['transactions'][2]

                print("\t\tSequence number: ", tran2['seq'], "Ack number: ",
                      tran2['ack'], "Receive Window size: ", tran2['win'])

                print("\t\tSequence number: ", tran3['seq'], "Ack number: ",
                      tran3['ack'], "Receive Window size: ", tran3['win'])

                print("\t* congestion window sizes estimation:")
                time_break = flows_forward[flow]['transactions'][0]['time']
                after_rtt = time_break + flows_forward[flow]['rtt']
                windows_size = 0
                window_count = 0
                for tran in flows_forward[flow]['transactions']:
                    if time_break <= tran['time'] <= after_rtt:
                        windows_size += 1
                    else:
                        print(f"\t\twindow#{window_count}: ", windows_size)
                        window_count += 1
                        windows_size = 0
                        time_break = tran['time']
                        after_rtt = time_break + flows_forward[flow]['rtt']
                        if window_count == 3:
                            break

                triple_re = []
                timeout_re = []
                special = []
                freq_dict = {}
                retransmission = []
                forward_seq = [(d['seq'], d['time']) for d in flows_forward[flow]['transactions']]
                for pair in forward_seq:
                    if pair[0] in freq_dict and freq_dict[pair[0]] == 1:
                        retransmission.append(pair)
                    else:
                        freq_dict[pair[0]] = 1
                reflow = (flow[2], flow[3], flow[0], flow[1])
                backward_ack = [(d['ack'], d['time']) for d in flows_backward[reflow]['transactions']]
                for pair in retransmission:
                    if count_duplicate_before(pair[1], pair[0], backward_ack) >= 3:
                        triple_re.append(pair)
                    elif time_diff_to_last_seq(pair[1], pair[0], forward_seq) > flows_forward[flow]['rto']:
                        timeout_re.append(pair)
                    else:
                        special.append(pair)
                print(f"\t* total retransmission: {len(retransmission)}")
                print(f"\t\tdue to triple duplicate: {len(triple_re)}")
                print(f"\t\tpossibly due to timeout: {len(timeout_re)}")
                print(f"\t\tspecial: {len(special)}")

                throughout = flows_forward[flow]['total bytes'] / (
                        flows_forward[flow]['end_time'] - flows_forward[flow]['start_time'])
                throughout /= 1000000
                print("\t* throughout: ", throughout, " Mbps\n")
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\nTOTAL NUMBER: ", sender_tcp_counter)


def count_duplicate_before(time, ack, pair_list):
    count = 0
    for pair in pair_list:
        if pair[1] < time and pair[0] == ack:
            count += 1
    return count


def time_diff_to_last_seq(time, seq, pair_list):
    for pair in pair_list:
        if pair[0] == seq:
            return time - pair[1]
    return 0


def main():
    analysis_pcap_tcp("tcp_test.pcap")


if __name__ == '__main__':
    main()
