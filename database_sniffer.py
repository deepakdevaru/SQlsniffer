#Publisher : Deepak Devaru Joshi

#Date: 11/26/2017

#Packet Sniffer
# A simple packet sniffer is designed to sniff packets for various packet attributes like Mac addresses, protocols,
#source and destination IP address, TTL, IP version, IP header length, total length of the ip header.



import socket
import struct
import sqlite3

connection=sqlite3.connect('Packet Sniffer')
c=connection.cursor()

class Table:
    def create_table(self):
        c.execute('CREATE TABLE IF NOT EXISTS sniffer(ip version VARCHAR(20), '
                  'ttl VARCHAR (20), src-ip TEXT, dest-ip TEXT, protocol TEXT, '
                  'src-mac TEXT, dest-mac TEXT, mac-type VARCHAR(20),src-port VARCHAR(20),dest-port VARCHAR(20),'
                  ' tcp-sequence VARCHAR(30), tcp-ack-no VARCHAR(30), '
                  'udp-length VARCHAR(30), udp-checksum  VARCHAR(30),'
                  ' icmp-type VARCHAR(30), icmp-code VARCHAR(30), icmp-checksum VARCHAR(30),'
                  'ip-header-length VARCHAR(20), ip-total-length VARCHAR(20), identification VARCHAR(30))')

    def enter_into_table(self,ip_version, ttl, src_ip, dest_ip, protocol,
                   src_mac, dest_mac, mac_type,src_port,dest_port,tcp_sequence, tcp_ack_no,udp_length, udp_checksum, icmp_type, icmp_code, icmp_checksum,ip_header_length, ip_total_length, identification):
        c.execute('INSERT INTO sniffer(ip version, ttl, src-ip, dest-ip, protocol , src-mac, dest-mac, mac-type,src-port,dest-port,tcp-sequence, tcp-ack-no, '
                  'udp-length, udp-checksum, icmp-type, icmp-code, icmp-checksum,ip-header-length, ip-total-length, identification) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (ip_version, ttl, src_ip, dest_ip, protocol,
                   src_mac, dest_mac, mac_type,src_port,dest_port,tcp_sequence, tcp_ack_no,udp_length, udp_checksum, icmp_type, icmp_code, icmp_checksum,ip_header_length, ip_total_length, identification) )
        connection.commit()

    def db (self, ip_version, ttl, src_ip, dest_ip, protocol,
            src_mac, dest_mac, mac_type,src_port,dest_port,tcp_sequence, tcp_ack_no,udp_length, udp_checksum, icmp_type, icmp_code, icmp_checksum,ip_header_length, ip_total_length, identification):

        t=Table()
        t.create_table()
        t.enter_into_table(self,ip_version, ttl, src_ip, dest_ip, protocol,
                            src_mac, dest_mac, mac_type,src_port,dest_port,tcp_sequence, tcp_ack_no,udp_length, udp_checksum, icmp_type, icmp_code, icmp_checksum,ip_header_length, ip_total_length, identification)

c.close()
connection.close()



def ethernet_unpack(pkt):
    dest_mac, src_mac,type= struct.unpack('!6s 6s H', pkt[:14])
    return mac_address(dest_mac), mac_address(src_mac) , socket.htons(type), pkt[14:]

#formating mac to AA:BB:CC format
def mac_address(address_data):
    bytes_string=B':'.join(["%02X" % (ord(x)) for x in address_data])
    return bytes_string.upper()


# To unpack the ip packet,
#ip version and header together form 8bits in the ip header table: hence B as it has size 1byte=8bits
#Differentaited services forms next 8bits in the header: hence B as it has size 1byte=8bits
#Total length, identification, (flags and fragment offset) forms the next 16bits each in the header: hence H as it hs size 2byte= 16bits
# TTL and Protocol occupies 8bits each in ip header: hence B each
#Header checksum= 16 bits . hecne H
#Source IP: 32 bits : hence 4s ( string of size 8*4)
#Destination IP: 32 bits : hence 4s ( string of size 8*4)
#reference IP table http://www.networksorcery.com/enp/protocol/ip.html
def IP_header_unpack(pkt):
    eth_length= 14
    unpack_data= struct.unpack('!B B H H H B B H 4s 4s', pkt[eth_length:20+eth_length])
    versionIHL= unpack_data[0] #unpack version and  IP header length

    version= versionIHL >> 4 # to extract version, bit shift by 4 bits as version occupies 4bits in iptable
    header_length =  (versionIHL & 0xf)*4

    # differentiated services not unpacked

    total_length=  unpack_data[2]
    identification= unpack_data[3]
    ttl=unpack_data[5]
    ip_protocol= unpack_data[6]

    protocol, source_port, dest_port, sequence, acknum, type, code, checksum, length, check_sum=protocol_decider(ip_protocol,header_length,eth_length,pkt)

    source_addr= socket.inet_ntoa(unpack_data[8]) #get source ip
    dest_addr=socket.inet_ntoa(unpack_data[9]) #get destination ip
    return version, header_length, total_length, identification,ttl,ip_protocol,source_addr,dest_addr,protocol,source_port,dest_port,sequence,acknum,type,code,checksum,length,check_sum


def protocol_decider(proto_number,header_length,eth_length,pkt):
    if proto_number== 6: #TCP

         protocol,source_port,dest_port,sequence,acknum = TCP_protocol (header_length,eth_length,pkt)
         print 'protocol: '+ str(protocol)
         print 'source port: '+ str(source_port)
         print 'destination port: ' +str(dest_port)
         print 'sequence: '+ str(sequence)
         print 'acknum: '+str(acknum)
         return #protocol,source_port,dest_port,sequence,acknum

    elif proto_number==1: #ICMP
        protocol,type1, code, checksum =ICMP_packet(header_length, eth_length, pkt)
        print 'protocol: ' + str(protocol)
        print 'type: ' + str(type1)
        print 'code: ' + str(code)
        print 'checksum: ' + str(checksum)
        return #protocol,type1,code,checksum

    elif proto_number==17: #UDP
        protocol,source_port, dest_port, length, check_sum= UDP_packet(header_length,eth_length,pkt)
        print 'protocol: ' + str(protocol)
        print 'source port: ' + str(source_port)
        print 'destination port: ' + str(dest_port)
        print 'length: ' + str(length)
        print 'checksum: ' + str(check_sum)
        return #protocol,source_port,dest_port,length,check_sum
    else:
        return 'some other protocol'

    return protocol,source_port,dest_port,sequence,acknum,type1,code,checksum,length,check_sum


#TCP Protocol unpack
    # TCP header table: http://www.networksorcery.com/enp/protocol/tcp.htm
    # take first 20 char of TCP header
    #unpack source port (16 bits) , destination port (16 bits), sequence number (32 bits long) and acknowledgement number (32 bits long)
    # not extracted: Data Offset 	reserved 	ECN 	Control Bits 	Window Checksum 	Urgent Pointer
def TCP_protocol (header_length,eth_length,pkt):
    t= header_length+eth_length
    TCP_Header= struct.unpack('! H H L L B B H H H', pkt[t:t+20]) #TCp length= 20bytes
    protocol= 'TCP'
    source_port= TCP_Header[0]
    dest_port= TCP_Header[1]
    sequence= TCP_Header[2]
    acknum= TCP_Header[3]
    TCP_datalog(protocol,source_port,dest_port,sequence,acknum)
    return protocol, source_port,dest_port,sequence,acknum


    #ICMP packet unpack
    #ICMP header table:http://www.networksorcery.com/enp/protocol/icmp.htm
    #unpack type(8 bits), code(8 bits) and checksum(16 bits)
def ICMP_packet(header_length,eth_length,pkt):
    i=header_length+eth_length
    ICMP_header= struct.unpack('!BBH', pkt[i:i+4]) # ICMP length =4bytes

    protocol = 'ICMP'
    type= ICMP_header[0]
    code= ICMP_header[1]
    checksum= ICMP_header[2]
    return protocol,type,code,checksum


#UDP packet unpack
#http://www.networksorcery.com/enp/protocol/udp.htm
#unpack source port (16 bits= H), destination port(16 bits= H), length (16 bits= H), chechsum(16 bits= H)
def UDP_packet(header_length,eth_length,pkt):
    u=header_length+eth_length
    UDP_header= struct.unpack('!HHHH', pkt[u:u+8]) #udp size 8bytes

    protocol='UDP'
    source_port= UDP_header[0]
    dest_port= UDP_header[1]
    length = UDP_header[2]
    check_sum= UDP_header[3]
    return protocol,source_port,dest_port,length,check_sum


def data_collection(raw_data):
    dest_mac, src_mac, mac_type, pkt = ethernet_unpack(raw_data)



def main():
    connection= socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3)) #ntohs(3) checks whether the data is in readable format like byte order, big endian
    while True:
        try:
            raw_data, addr = connection.recvfrom(655536)
        except socket.timeout:
            print ' error in receiving data'

        dest_mac, src_mac,mac_type,pkt= ethernet_unpack(raw_data)
        ip_version, header_length, total_length, identification,ttl,ip_protocol,source_addr,dest_addr,protocol,source_port,dest_port,sequence,acknum,icmp_type,code,icmp_checksum,length,udp_check_sum = IP_header_unpack(raw_data)
        print (' dest_mac: ' +dest_mac + ' source_mac: '+ src_mac+' type: '+str(mac_type))
        print ''
        print ('ip version: '+str(ip_version)+ ' header length: ' +str(header_length)+ ' total length: '+ str(total_length)+ ' identification: ' + str(identification)
               + ' TTL: ' +str(ttl)+ ' source ip: ' +str(source_addr)+ ' destination ip: '+ str(dest_addr) + ' ip protocol: '+ str(ip_protocol))
        print''
        print''

        data_collection(raw_data)
        a= Table()
        a.db(ip_version,ttl,source_addr,dest_addr,protocol,src_mac,dest_mac,mac_type,source_port,dest_port,sequence,acknum,length,udp_check_sum,icmp_type,code,icmp_checksum,header_length,total_length,identification)

main()
