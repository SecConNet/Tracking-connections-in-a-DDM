#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header _with_ options
header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
    varbit<320>  options;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum; // Includes Pseudo Hdr + TCP segment (hdr + payload)
    bit<16> urgentPtr;
    varbit<320>  options;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header IPv4_up_to_ihl_only_h {
    bit<4>       version;
    bit<4>       ihl;
}

header tcp_upto_data_offset_only_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    // dataOffset in TCP hdr uses 4 bits but needs padding.
    // If 4 bits are used for it, p4c-bm2-ss complains the header
    // is not a multiple of 8 bits.
    bit<4>  dataOffset;
    bit<4>  dontCare;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    tcp_t                tcp;
    udp_t                udp;
}

struct mystruct1_t {
    bit<4>  a;
    bit<4>  b;
}

struct metadata {
    mystruct1_t mystruct1;
    bit<16>     l4Len; // includes TCP hdr len + TCP payload len in bytes.
}

typedef tuple<
    bit<4>,
    bit<4>,
    bit<8>,
    varbit<56>
    > myTuple1;

// Declare user-defined errors that may be signaled during parsing
error {
    IPv4HeaderTooShort,
    TCPHeaderTooShort,
    IPv4IncorrectVersion,
    IPv4ChecksumError
}

parser parserI(packet_in pkt,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        // The 4-bit IHL field of the IPv4 base header is the number
        // of 32-bit words in the entire IPv4 header.  It is an error
        // for it to be less than 5.  There are only IPv4 options
        // present if the value is at least 6.  The length of the IPv4
        // options alone, without the 20-byte base header, is thus ((4
        // * ihl) - 20) bytes, or 8 times that many bits.
        pkt.extract(hdr.ipv4,
                    (bit<32>)
                    (8 *
                     (4 * (bit<9>) (pkt.lookahead<IPv4_up_to_ihl_only_h>().ihl)
                      - 20)));
        verify(hdr.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hdr.ipv4.ihl >= 4w5, error.IPv4HeaderTooShort);
        meta.l4Len = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl)*4;
        transition select (hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        // The 4-bit dataOffset field of the TCP base header is the number
        // of 32-bit words in the entire TCP header.  It is an error
        // for it to be less than 5.  There are only TCP options
        // present if the value is at least 6.  The length of the TCP
        // options alone, without the 20-byte base header, is thus ((4
        // * dataOffset) - 20) bytes, or 8 times that many bits.
        pkt.extract(hdr.tcp,
                    (bit<32>)
                    (8 *
                     (4 * (bit<9>) (pkt.lookahead<tcp_upto_data_offset_only_h>().dataOffset)
                      - 20)));
        verify(hdr.tcp.dataOffset >= 4w5, error.TCPHeaderTooShort);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

}

control cIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta)
{

   @name("counting_asset") register<bit<32>>(100) counting_asset;
   bit<32> x;
   @name("payload") register<bit<32>>(10) payload;
   @name ("packet_last_time") register <bit<48>> (10) packet_last_time;
   @name ("time_interval") register <bit<48>> (10) time_interval;

    action send_to_nat(bit<48> src_mac,bit<48> dst_mac,bit<32> src_ip, bit<32> dst_ip, bit<9> port){
        hdr.ethernet.srcAddr=src_mac;
        hdr.ethernet.dstAddr=dst_mac;
        hdr.ipv4.dstAddr=dst_ip;
        hdr.ipv4.srcAddr=src_ip;
        stdmeta.egress_spec = port;

    }

    action save_time (bit<48> src_mac,bit<48> dst_mac,bit<32> src_ip, bit<32> dst_ip, bit<9> port) {
	
	hdr.ethernet.srcAddr=src_mac;
        hdr.ethernet.dstAddr=dst_mac;
        hdr.ipv4.dstAddr=dst_ip;
        hdr.ipv4.srcAddr=src_ip;
        stdmeta.egress_spec = port;
	payload.read(x, (bit<32>)hdr.tcp.dstPort);
	x = x + (bit<32>)hdr.ipv4.totalLen;
	payload.write((bit<32>)hdr.tcp.dstPort , x);
	packet_last_time.write( (bit<32>)hdr.tcp.dstPort, stdmeta.ingress_global_timestamp);
	        
	}


    action count_access (bit<48> src_mac,bit<48> dst_mac,bit<32> src_ip, bit<32> dst_ip, bit<9> port){
	@atomic{
	counting_asset.read(x,(bit<32>)hdr.tcp.dstPort);
	x =  x + 1;
        counting_asset.write( (bit<32>)hdr.tcp.dstPort , x);
	hdr.ethernet.srcAddr=src_mac;
        hdr.ethernet.dstAddr=dst_mac;
        hdr.ipv4.dstAddr=dst_ip;
        hdr.ipv4.srcAddr=src_ip;
        stdmeta.egress_spec = port;
	}
	}



      action decrease_access (bit<48> src_mac,bit<48> dst_mac,bit<32> src_ip, bit<32> dst_ip, bit<9> port){
	@atomic{
        counting_asset.read(x,(bit<32>)hdr.tcp.dstPort);
        x =  x - 1;
        counting_asset.write( (bit<32>)hdr.tcp.dstPort , x);
        hdr.ethernet.srcAddr=src_mac;
        hdr.ethernet.dstAddr=dst_mac;
        hdr.ipv4.dstAddr=dst_ip;
        hdr.ipv4.srcAddr=src_ip;
        stdmeta.egress_spec = port;
        }
        }


      action send_to_client(bit<48> src_mac,bit<48> dst_mac,bit<32> src_ip, bit<32> dst_ip, bit<9> port){
	hdr.ethernet.srcAddr=src_mac;
        hdr.ethernet.dstAddr=dst_mac;
        hdr.ipv4.dstAddr=dst_ip;
        hdr.ipv4.srcAddr=src_ip;
        stdmeta.egress_spec = port;



	}


    table count_number_of_flows{
	key = {
		hdr.ipv4.dstAddr : lpm;
	}
	actions = {count_access;NoAction;}
	default_action = NoAction;

    }



    table ipv4_match {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {send_to_nat;NoAction; }
        default_action = NoAction;
    }



    table decrease_number_of_flows {
	key = {
		hdr.ipv4.dstAddr : lpm;
	}
	actions = {decrease_access;NoAction;}
        default_action = NoAction;
      }



    table tcp_port_match {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = {save_time;NoAction; }
        default_action = NoAction;
    }

    table tcp_srcport_match {
	key = {
	   hdr.tcp.srcPort :exact;
	}
	actions = {send_to_client; NoAction; }
	default_action = NoAction;
	}

    apply {
	@atomic{
	    bit <48> t_max ;
	    bit <48> t_last ;
	    bit <48> t_difference;
	    time_interval.read ( t_max, (bit<32>) hdr.tcp.dstPort);
	    packet_last_time.read (t_last, (bit<32>) hdr.tcp.dstPort);
            if (t_last != 0 ){
	    t_difference = stdmeta.ingress_global_timestamp - t_last ;
	    if (t_difference > t_max ) {

		time_interval.write ((bit<32>) hdr.tcp.dstPort, t_difference);
	
		}
	    }
      tcp_port_match.apply();
 	    tcp_srcport_match.apply();
	}
}
}





control cEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta)
{
    apply {
    }
}

control vc(inout headers hdr,
           inout metadata meta)
{
    apply {
        verify_checksum(true,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.options
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4Len,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                16w0,
                hdr.tcp.urgentPtr,
                hdr.tcp.options
            },
            hdr.tcp.checksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(hdr.udp.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4Len,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length_
            },
            hdr.udp.checksum, HashAlgorithm.csum16);
    }
}

control uc(inout headers hdr,
           inout metadata meta)
{
    apply {
        update_checksum(true,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.options
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);

        update_checksum_with_payload(hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4Len,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                16w0,
                hdr.tcp.urgentPtr,
                hdr.tcp.options
            },
            hdr.tcp.checksum, HashAlgorithm.csum16);
        update_checksum_with_payload(hdr.udp.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4Len,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length_
            },
            hdr.udp.checksum, HashAlgorithm.csum16);
    }
}

control DeparserI(packet_out packet,
                  in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch<headers, metadata>(parserI(),
                            vc(),
                            cIngress(),
                            cEgress(),
                            uc(),
                            DeparserI()) main;
