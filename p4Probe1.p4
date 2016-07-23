//***************NETRONOME WEBINAR SERIES REFERENCE CODE-WEBINAR 1-P4Probe**********************
/*

This is the P4 code for the P4 probe app, please note this is the original code and is not yet optimised.

I hope to release an optimized version of this code at some point in the near future (if I have time).

Please note the use of a primitive C action file in conjunction with this file.

*/

#define VSLICE_ETYPE  0x9999 //we have given vslice packets their own ethernet type for handli
#define VSLICE_STATIC_IOT 0x3 //these definitions are currently unused but are useful reference for C sandbox file
#define VSLICE_BROADBAND 0x2
#define VSLICE_VOICE  0x1
#define VSLICE_MISSION_CRITICAL_IOT 0x0
#define ARP_ETYPE 0x806
#define IPV4_ETYPE 0x0800
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

//---------------------Header Definitions------------------------

header_type eth_hdr {
	fields {
		dst : 48;
		src : 48;
		etype : 16;
	}
}

header_type vslice_hdr {
	fields {
		slice : 8;	//Slice id
		etype : 16;	//correct etype of packet inside vslice header-
					//this is to ensure that the packet is correctly
					//reassembled for the host to process without having to know about the slicing
	}
}


header_type ipv4_hdr {
	fields {
		ver : 4;
		ihl : 4;
		tos : 8;
		len : 16;
		id : 16;
		frag : 16;
		ttl : 8;
		proto : 8;
		csum : 16;
		src : 32;
		dst : 32;
	}
}

header_type udp_hdr {
	fields {
		srcprt : 16;
		dstprt : 16;
		udplen : 16;
		udpchk : 16;
	}
}

header_type tcp_hdr {
	fields {
		srcprt : 16;
		dstprt : 16;
		seqnum : 32;
		acknum : 32;
		offset : 4;
		res : 6;
		urg : 1;
		ack : 1;
		psh : 1;
		rst : 1;
		syn : 1;
		fin : 1;
		window : 16;
		tcpchk : 16;
		urgpntr : 16;
	}
}
		
//----------------------Header Declarations------------

header eth_hdr eth;

//header arp_hdr arp;

header ipv4_hdr ipv4;

header tcp_hdr tcp;

header udp_hdr udp;  

header vslice_hdr vslice;

//----------------------Parsing---------------------------

parser start {
	return eth_parse;
}

parser eth_parse {
	extract(eth);
	return select(eth.etype) {
		VSLICE_ETYPE: vslice_parse;
		IPV4_ETYPE: ipv4_parse;
		default: ingress;
	}
}

parser ipv4_parse {
	extract(ipv4);
	return select(ipv4.proto) {
		TCP_PROTO: tcp_parse;
		UDP_PROTO: udp_parse;
		default: ingress;
	}
}

parser vslice_parse {
	extract(vslice);
	return select(vslice.etype)
	{
		IPV4_ETYPE: ipv4_parse;
		default: ingress;
	}
}


parser tcp_parse {
	extract(tcp);
	return ingress;
}

parser udp_parse {
	extract(udp);
	return ingress;
}


//-----------------Action Definitions-----------------------------


primitive_action filter_func(); //Note Primitive Action-this is the C sandbox being called

action drop_act() {
	drop();
}
action broadcast_act(grp) {
	modify_field(standard_metadata.egress_spec, grp); //demonstrates how to broadcast to group
}
action fwd_act(prt) {
	
	modify_field(standard_metadata.egress_spec, prt); //send to correct egress queue for specified match
}
action encap_act(prt, tag) {
	
	vslice_encap(tag); //encapsulate with vslice specified by the match see action vslice_encap below
	fwd_act(prt);		//call forward action above
}
action decap_act(prt,tag) {
	filter_func();
	modify_field(standard_metadata.egress_spec, prt); 
	modify_field(eth.etype, IPV4_ETYPE); //reinsertion of correct IPV4 etype-this could be
										 //gathered from vslice.etype in situation with more types of layer 3 headers
	remove_header(vslice); //removal of vslice header
	drop();
}
action vslice_encap(tag) {
	add_header(vslice);
	modify_field(vslice.slice, tag);
	modify_field(vslice.etype, eth.etype);	//insert the encapsulated packets ethernet type into vslice to use at decap
	modify_field(eth.etype, VSLICE_ETYPE); //insert the vslice etype into the ethernet header
}

 
//----------------------------Match Tables------------------


table encap_tcp_tbl {
	reads {
		standard_metadata.ingress_port : exact;	//fields to match on
		tcp.srcprt : exact;
	}
	actions {
		encap_act;	//actions to use those match fields on to find correct action
		fwd_act; 
	}  
}

//the structure above is repeated below

table encap_udp_tbl {
	reads {
		standard_metadata.ingress_port : exact;
		//udp.srcprt : exact;
	}
	actions {
		encap_act;
		fwd_act; 
	}  
}


table decap_tbl {
	reads {
		vslice.slice : exact;
	}
	actions {
		decap_act;
	}
}

table arp_tbl { //note this is action for imaginary ARP packets which are not defined in this exampel, for demonstration only
	reads {
		standard_metadata.ingress_port : exact;
	}
	actions {
		broadcast_act;
	}
}

table fwd_ip_tbl {
	reads {

		standard_metadata.ingress_port : exact;
		ipv4.dst : exact;
	}
	actions {
		fwd_act;
		drop_act;
	}
}

table fwd_eth_tbl {
	reads {

		standard_metadata.ingress_port : exact;
		eth.dst : exact;
	}
	actions {
		fwd_act;
	}
}

table drop_tbl {
	actions {
		drop_act;
	}
}

//-------------------Control Flow-------------------------------

control ingress {
	if (valid(vslice))							
	{
		apply(decap_tbl);		//vslice encapped packets
	} else if (valid(ipv4))		//ipv4 packets
		{
			if (valid(tcp))
			{
				apply(encap_tcp_tbl);	//tcp encap
			}
			else if (valid(udp))
			{
				apply(encap_udp_tbl);	//udp encap
			}
			else
			{
				apply(fwd_ip_tbl);	//other ipv4 forwarded
			}
			
		}
		else					//unknown packet type-drop
		{
			apply(drop_tbl);
		}

}

 