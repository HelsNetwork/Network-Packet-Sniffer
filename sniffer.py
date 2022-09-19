import socket
import struct
import textwrap 





tab = lambda num: "\t"*num



def main():

    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    while True:
       raw_data, addr = s.recvfrom(65565)
       dest_mac, src_mac, eth_proto,data = ethernet_frame(raw_data)
       print('\nEthernet Frame: ')
       print(tab(1)+ f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}' )
       
       #IPV4
       if eth_proto == 8:
            (version, header_length, ttl, proto, src,target, data) = ipv4_packet(data)
            print(tab(1) + 'ipv4 packet: ')
            print(tab(2) + f'version: {version}, Header Lenght: {header_length}, TTL: {ttl} , Protocol: {proto}, Source: {src}, target: {target}')
        
            #ICMP
            if proto == 1:
                cmp_type, code, checksum, data = icmp_packet(data)
                print(tab(1) + 'ICMP Packet: ')
                print(tab(2) + f'Type: {cmp_type}, Code: {code}, Checksum: {checksum}')
                print(tab(2) + 'Data: ')
                print(format_multi_line(tab(3),data))

            #TCP
            elif proto == 6:
                (src_port, dest_port,acknowlegement, ack, sync, urg, psh,rst, fin,sequence, data) = tcp_segment(data)
                print(tab(1) + 'TCP Segment: ')
                print(tab(2) + f'Source Port: {src_port},  Destination Port: {dest_port}, sequence: {sequence} Acknowlegement: {acknowlegement}')
                print(tab(2) + 'Flags: ')
                print(tab(3) + f'URG{urg}, ACK{ack}, SYNC{sync}, PSH{psh}, RST{rst}, FIN{fin}' )
                print(tab(2) + 'Data: ')
                print(format_multi_line(tab(3),data))

            #UDP
            elif proto == 17:
                (src_port, dest_port, length, data) = udp_segment(data)
                print(tab(1) + 'UDP Segment: ')
                print(tab(2) + f'Source Port: {src_port}, Destination Port: {dest_port}, Lenght: {length}')
                print(tab(2) + 'Data: ')
                print(format_multi_line(tab(3),data))
            #Other
            else: 
                print(tab(1) + 'Data: ')
                print(format_multi_line(tab(2),data))
       else: 
                print(tab(1) + 'Data: ')
                print(format_multi_line(tab(1),data))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpack IPv4 Packets Recieved
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    return '.'.join(map(str, addr))


#Unpack the icmp packet 
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data [:4])
    return icmp_type, code, checksum, data[4:]



#Unpack the TCP packet
def tcp_segment(data):
    (src_port, dest_port, ackacknowlegement, offest_reserverd, sequence) = struct.unpack('!HHLLH', data[:14])
    offset = (offest_reserverd >> 12) *4
    ack = (offest_reserverd & 32) >> 5
    sync = (offest_reserverd & 16) >> 4
    urg = (offest_reserverd & 8) >> 3
    psh = (offest_reserverd & 4) >> 2
    rst = (offest_reserverd & 2) >> 1
    fin = offest_reserverd & 1
    return src_port, dest_port, ackacknowlegement, offest_reserverd, ack, sync, urg, psh,rst, fin, data[offset:]

 


# Unpack a UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    
    return  src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)  
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])




main()
