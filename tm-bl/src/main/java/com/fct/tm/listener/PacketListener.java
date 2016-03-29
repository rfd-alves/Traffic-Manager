package com.fct.tm.listener;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fct.tm.handler.DnsPacketHandler;
import com.fct.tm.listener.SwitchListener;
import com.fct.tm.handler.StatePacketHandler;
import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.ErrorEvent;
import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.ctl.pkt.PacketListenerRole;
import com.hp.of.ctl.pkt.SequencedPacketListener;
import com.hp.of.lib.OpenflowException;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.DataPathId;
import com.hp.of.lib.dt.MeterId;
import com.hp.of.lib.dt.TableId;
import com.hp.of.lib.instr.ActOutput;
import com.hp.of.lib.instr.Action;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.instr.InstrMutableAction;
import com.hp.of.lib.instr.Instruction;
import com.hp.of.lib.instr.InstructionFactory;
import com.hp.of.lib.instr.InstructionType;
import com.hp.of.lib.match.FieldFactory;
import com.hp.of.lib.match.Match;
import com.hp.of.lib.match.MatchFactory;
import com.hp.of.lib.match.MutableMatch;
import com.hp.of.lib.match.OxmBasicFieldType;
import com.hp.of.lib.msg.FlowModCommand;
import com.hp.of.lib.msg.FlowModFlag;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.of.lib.msg.OfmMutablePacketOut;
import com.hp.of.lib.msg.OfmPacketIn;
import com.hp.of.lib.msg.Port;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.ICMPv4Type;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;
import com.hp.util.pkt.Codec;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.ProtocolId;

public class PacketListener implements SequencedPacketListener{
	
	private static final int ALTITUDE = 60000;
	
	private static ControllerService mControllerService;
	private static final Logger LOG = LoggerFactory.getLogger(PacketListener.class);
    public static final short   TYPE_8021X = (short) 0x888e;
    public static final short   TYPE_IPv4  = 0x0800;
    public static final short   RADIUS_PORT  = 0x0714;
    public static final byte   ICMP  = 0x01;
    public static final byte   UDP  = 0x11;
    public static final byte   TCP  = 0x06;
    public static final byte   ACCESS_REQUEST  = 0x01;
    public static final byte   ACCESS_ACCEPT  = 0x02;
    public static final byte   ACCESS_REJECT  = 0x03;
    public static final byte   ACCESS_CHALLENGE  = 0x0b;
    //private static byte[] STATE;
    public static final String IP_ADDR_CONT = "192.168.56.101";//{(byte)0xc0,(byte)0xa8,0x38,0x65};//192.168.56.101
    public static final String IP_GATEWAY = "192.168.0.1";
    public static final String MAC_GATEWAY = "00:13:f7:71:22:26";
    public static final String MAC_ADDR_CONT ="08:00:27:07:41:c7"; //{0x08,0x00,0x27,0x07,0x41,(byte)0xc7};//192.168.56.101
    public static List<StatePacketHandler> Conv_ID= new ArrayList<StatePacketHandler>();
    private static final String shared = "testing123";
	private static final long COOKIE = 0x00002468;
	private static final TableId TABLE_ID = TableId.valueOf(100);
	private static final int FLOW_IDLE_TIMEOUT = 0;
	private static final int FLOW_HARD_TIMEOUT = 0;
	private static final Set<FlowModFlag> FLAGS = EnumSet.of(
			FlowModFlag.SEND_FLOW_REM,
			//FlowModFlag.CHECK_OVERLAP,
			FlowModFlag.NO_BYTE_COUNTS
	);
	private static final String RADIUS_IP = "172.16.4.152";//10.0.0.2
	private static final String RADIUS_MAC = "d0:27:88:6f:1c:23";//d0:27:88:6f:1c:3e 00:00:00:00:00:02
	private static final BigPortNumber RADIUS_SWI_PORT = BigPortNumber.valueOf(2);
	private static final DataPathId RADIUS_SWI = DataPathId.dpid("00:00:00:00:00:00:00:01");







	public void init(final ControllerService controllerService ){
		LOG.info("TrafficManager:PacketListener Initiated!!!");
		mControllerService = controllerService;
	}
	
	public void startUp(){
		mControllerService.addPacketListener(this, PacketListenerRole.DIRECTOR, ALTITUDE);
		LOG.info("TrafficManager:PacketListener2 Started!!!");
	}
	
	public void shutDown(){
		mControllerService.removePacketListener(this);
		LOG.info("TrafficManager:PacketListener Finished!!!");

	}

	@Override
	public void errorEvent(ErrorEvent event) {
		LOG.error( "TrafficManager:PacketListener errorEvent(): Received error event: " + event.text() );
		
	}

	@Override
	public void event(MessageContext messageContext){
        // Get incoming packet from switch, and the packet data as well
        OfmPacketIn ofPacketIn = (OfmPacketIn)messageContext.srcEvent().msg();
        Packet packetInData  = Codec.decodeEthernet( ofPacketIn.getData() );
        short etherType = 0;
        byte type=0;
        
		LOG.info("TrafficManager:PacketListener received package={}.", ofPacketIn);
    	DataInputStream packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
    	try {
        	// Skip Ethernet header: dst(6) and source(6) MAC, DataLayer type(2),
			packetDataInputStream.skip(6 + 6); 
			etherType = packetDataInputStream.readShort();
	    	//LOG.info("TrafficManager:PacketListener received Protocol= " + String.format("%04X ", etherType));
		} catch (IOException e) {
	    	LOG.info("TrafficManager:PacketListener error EtherType = {}",e);
		}



		
		
		//---- Handle DNS request here --------------------     
//        if( packetInData.has( ProtocolId.DNS ) ) {
//
//        	DnsPacketHandler dnsPacketHandler = new DnsPacketHandler();
//        	if(dnsPacketHandler.handle(messageContext, ofPacketIn)){
//        		LOG.trace( "TrafficManager:PacketListener event(): allowing DNS request to be forwarded" );
//        		// If allowed, add a 'forward normal' action to the outgoing packet.
//
//        	}else{
//        		LOG.trace( "TrafficManager:PacketListener event(): bad DNS requested, dropping packet." );
//        	}
//       		
//        }
        
        //---- Handle non-DNS IP requests here ------------
       if(packetInData.has(ProtocolId.IP)){
    	   try {
    		   packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
    		   byte[] target_mac = new byte[6];
    		   packetDataInputStream.read(target_mac, 0, 6);
    		   // Skip Ethernet header:  source(6) MAC, DataLayer type(2); some of IP Header(9),
			   packetDataInputStream.skip(6 + 2 + 9);
			   byte ip_protocol = packetDataInputStream.readByte();
			   if(ip_protocol == UDP){
				   // Skip rest Ip Header(10)
				   packetDataInputStream.skip(10);
				   short src_port = packetDataInputStream.readShort();
				   short dst_port = packetDataInputStream.readShort();
				   if(src_port==RADIUS_PORT || dst_port==RADIUS_PORT){
					   // Skip rest UDP Header(6)
					   packetDataInputStream.skip(4);
					   if(Arrays.equals(MacAddress.mac(MAC_ADDR_CONT).toByteArray(), target_mac)){
						   byte radius_code = packetDataInputStream.readByte();
						   byte packet_id = packetDataInputStream.readByte();
						   int pos=-1;
						   for (StatePacketHandler temp : Conv_ID) {
								if(temp.getPacket_id()==packet_id){
									pos=Conv_ID.indexOf(temp);
								}
									
						   }
						   int radius_length = packetDataInputStream.readShort();
						   packetDataInputStream.skip(16);
						   radius_length= (radius_length - 20);
						   int i=0;
						   byte[] eap_message= new byte[0];
						   while(i<radius_length){
							   byte radius_atr_type = packetDataInputStream.readByte();
							   int radius_atr_length = (int) packetDataInputStream.readByte() & 0xFF;
							   byte[] radius_atr_data = new byte[radius_atr_length-2];
							   packetDataInputStream.read(radius_atr_data,0,radius_atr_length-2);
							   i=i+radius_atr_length;
							   if(radius_atr_type==(byte)0x18){
								   StatePacketHandler temp = Conv_ID.get(pos);
								   temp.setState(radius_atr_data);
								   Conv_ID.set(pos, temp);
							   }
							   if(radius_atr_type==(byte) 0x4f){
								   if(eap_message.length>0){
									   byte[] aux_1=eap_message;
									   eap_message=new byte[aux_1.length+radius_atr_data.length];
									   System.arraycopy(aux_1, 0, eap_message, 0, aux_1.length);
									   System.arraycopy(radius_atr_data, 0, eap_message, aux_1.length, radius_atr_data.length);
								   }else{
									   eap_message=radius_atr_data;
								   }
							   }
						   }
						   packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
						   packetDataInputStream.skip(42);
						   byte[] temp = new byte[radius_length+20];
						   packetDataInputStream.read(temp, 0, radius_length+20);
						   try {
							   if(check_Radius_auth(temp, Conv_ID.get(pos).getAuth())){
									   try {
										   OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
										   //0180c2000003
										   byte[] EAP_header = hexStringToByteArray("0180c20000030800270741c7888e0200");
										   byte[] EAP_length = new byte[2];
										   EAP_length[0]=(byte) ((eap_message.length >>> 8) & 0xFF);
										   EAP_length[1]=(byte) (eap_message.length & 0xFF);
										   byte[] EAP_msg = new byte[eap_message.length + EAP_header.length+EAP_length.length];
										   System.arraycopy(EAP_header, 0, EAP_msg, 0, EAP_header.length);
										   System.arraycopy(EAP_length, 0, EAP_msg, EAP_header.length, EAP_length.length);
										   System.arraycopy(eap_message, 0, EAP_msg, EAP_length.length+EAP_header.length, eap_message.length);
										   pktOut.data(EAP_msg);
										   pktOut.bufferId(ofPacketIn.getBufferId());
										   pktOut.inPort(Port.CONTROLLER);
										   pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Conv_ID.get(pos).getPort() ));
										   mControllerService.send(pktOut.toImmutable(), Conv_ID.get(pos).getDpid());
										   LOG.info( "TrafficManager:PacketListener event(): allowing EAPOL challenge to be forwarded" );
										   if(radius_code==ACCESS_ACCEPT){
											   set_flows(pos);
										   }
									   }catch (OpenflowException e) {
										   LOG.info( "TrafficManager:PacketListener EAP Challenge Packet error: exception: {}",e );
									   }
										  
								}
						   }catch (NoSuchAlgorithmException e) {
							   LOG.info( "TrafficManager:PacketListener Radius Check error: exception: {}",e );

						   }
						   
						   
					   }else{
						   //LOG.info( "TrafficManager:PacketListener event(): Radius packet ap." );
						   byte radius_code = packetDataInputStream.readByte();
						   byte packet_id = packetDataInputStream.readByte();
						   int radius_length = packetDataInputStream.readShort();
						   packetDataInputStream.skip(16);
						   radius_length= (radius_length - 20);
						   int i=0,pos=-1;
						   while(i<radius_length){
							   byte radius_atr_type = packetDataInputStream.readByte();
							   int radius_atr_length = (int) packetDataInputStream.readByte() & 0xFF;
							   byte[] radius_atr_data = new byte[radius_atr_length-2];
							   packetDataInputStream.read(radius_atr_data,0,radius_atr_length-2);
							   i=i+radius_atr_length;
							   if(radius_atr_type==(byte)0x18){//State
								   for(int j=0;j<Conv_ID.size();j++){
									   if(Arrays.equals(Conv_ID.get(j).getState(),radius_atr_data)){
										   pos=j;
									   }
								   }
								   break;
							   }  
						   }
						   LOG.info( "TrafficManager:PacketListener event(): Radius packet ap code= {}, pkt_id= {}.",radius_code, packet_id );
						   if(radius_code == ACCESS_REQUEST){
							   packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
							   packetDataInputStream.skip(62);
							   i=0;
							   if(pos==-1){
								   byte[] user_id=null, user_mac=null;
								   while(i<radius_length){
									   byte radius_atr_type = packetDataInputStream.readByte();
									   int radius_atr_length = (int) packetDataInputStream.readByte() & 0xFF;
									   byte[] radius_atr_data = new byte[radius_atr_length-2];
									   packetDataInputStream.read(radius_atr_data,0,radius_atr_length-2);
									   i=i+radius_atr_length;
									   if(radius_atr_type==(byte)0x01){
										   user_id=radius_atr_data;
									   }
									   if(radius_atr_type==(byte)0x1f){
										   user_mac=radius_atr_data;
									   }
									   
								   }
								   String s = new String(user_mac, "UTF-8");
								   String[] mac_parts = s.split("-");
								   user_mac = new byte[6];
								   Integer hex;
								   for(int j=0; j<6; j++){
									    hex = Integer.parseInt(mac_parts[j], 16);
									    user_mac[j] = hex.byteValue();
								   }
								   int pos2=-1;
								   for(int j=0;j<Conv_ID.size();j++){
									   if(Arrays.equals(Conv_ID.get(j).getUser(),user_id)){
										   pos2=j;
									   }
								   }
								   if(pos2==-1){
									   StatePacketHandler aux= new StatePacketHandler(user_mac,user_id,ofPacketIn.getInPort(),messageContext.srcEvent().dpid());
									   Conv_ID.add(aux);
									   Conv_ID.get(Conv_ID.size()-1).setPacket_id(packet_id);
									   LOG.info( "TrafficManager:PacketListener event(): added new user ap: {}.", Hex.encodeHexString(user_mac));
								   }else{
									   Conv_ID.get(pos2).setMac(user_mac);
									   Conv_ID.get(pos2).setDpid(messageContext.srcEvent().dpid());
									   Conv_ID.get(pos2).setPort(ofPacketIn.getInPort());
									   LOG.info( "TrafficManager:PacketListener event(): updated user ap: {}.", Hex.encodeHexString(user_mac));
	
								   }
							   }else{ 
								   Conv_ID.get(pos).setPacket_id(packet_id);
								   LOG.info( "TrafficManager:PacketListener event(): updated user pkt_id: {}.", Conv_ID.get(pos).getPacket_id());

							   }
							   
						   }
						   if(radius_code == ACCESS_CHALLENGE && pos==-1){
							   packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
							   packetDataInputStream.skip(62);
							   for(int j=0;j<Conv_ID.size();j++){
								   if(Conv_ID.get(j).getPacket_id()==packet_id){
									   i=0;
									   while(i<radius_length){
										   byte radius_atr_type = packetDataInputStream.readByte();
										   int radius_atr_length = (int) packetDataInputStream.readByte() & 0xFF;
										   byte[] radius_atr_data = new byte[radius_atr_length-2];
										   packetDataInputStream.read(radius_atr_data,0,radius_atr_length-2);
										   i=i+radius_atr_length;
										   if(radius_atr_type==(byte)0x18){//State
											   Conv_ID.get(j).setState(radius_atr_data);
											   break;
										   }  
									   }break;
								   }
							   }
						   }
						   if(radius_code==ACCESS_ACCEPT){
							   LOG.info( "TrafficManager:PacketListener event(): ACCESS ACCEPT." );
							   pos=-1;
							   for(int j=0;j<Conv_ID.size();j++){
								   if(packet_id==Conv_ID.get(j).getPacket_id()){
									   pos=j;
									   break;
								   }
							   }
							   if(pos!=-1){
								   set_flows(pos);
							   }
						   }
						   Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
						   messageContext.packetOut().addAction( action );
						   messageContext.packetOut().send();
						   LOG.info( "TrafficManager:PacketListener event(): allowing Radius packet to be forwarded." );
					   }
					   
				   }else{
					   Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
					   messageContext.packetOut().addAction( action );
					   messageContext.packetOut().send();
					   LOG.info( "TrafficManager:PacketListener event(): allowing IP_UDP request to be forwarded." ); 
				   }
    		   }else if(ip_protocol == ICMP){
    			   //drop the packets
    			   }else{
    				   	Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
               			messageContext.packetOut().addAction( action );
               			messageContext.packetOut().send();
               			LOG.info( "TrafficManager:PacketListener event(): allowing IP request to be forwarded." );
    			   
    			   }
	    	   //LOG.info( "TrafficManager:PacketListener event(): IP request." );
    	   } catch (IOException e) {
   	    	LOG.info( "TrafficManager:PacketListener IP Packet error: exception: {}",e );
    	   }
        }
        else if(packetInData.has(ProtocolId.ARP)){
          	try{
          		packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
          		// Skip Everything except target ip
          		packetDataInputStream.skip(38);
          		byte[] target_ip = new byte[4];
    	  		packetDataInputStream.read(target_ip, 0, 4);
    	  		if(Arrays.equals(target_ip, IpAddress.ip(IP_ADDR_CONT).toByteArray())){
	          		//000000000002080027c448d108060001080006040002080027c448d1c0a838650000000000020a000002
	          		OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
	          		byte[] dta = hexStringToByteArray("0000000000020800270741c7080600010800060400020800270741c7c0a838650000000000020a000002");
	          		pktOut.data(dta);
	            	pktOut.bufferId(ofPacketIn.getBufferId());
	            	pktOut.inPort(Port.CONTROLLER);
	            	pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, ofPacketIn.getInPort() ));
	            	mControllerService.send(pktOut.toImmutable(), messageContext.srcEvent().dpid());
	            	//LOG.info( "TrafficManager:PacketListener event(): ARP response sent." );
    	  		}else if(Arrays.equals(target_ip, IpAddress.ip(IP_GATEWAY).toByteArray())){
    	  				LOG.info( "TrafficManager:PacketListener event(): ARP GATEWAY." );
    	  				packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
	    	  			OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
	    	  			byte[] dta = build_ARP_packet(packetDataInputStream, MAC_GATEWAY);
		          		//byte[] dta = hexStringToByteArray("0000000000020800270741c7080600010800060400020800270741c7c0a838650000000000020a000002");
		          		pktOut.data(dta);
		            	pktOut.bufferId(ofPacketIn.getBufferId());
		            	pktOut.inPort(Port.CONTROLLER);
		            	pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, ofPacketIn.getInPort() ));
		            	mControllerService.send(pktOut.toImmutable(), messageContext.srcEvent().dpid());
		            	LOG.info( "TrafficManager:PacketListener event(): ARP GATEWAY SENT." );
    	  			}
    	  			else{
    	  		
    	  			Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
                	messageContext.packetOut().addAction( action );
                	messageContext.packetOut().send();
	            	LOG.info( "TrafficManager:PacketListener event(): allowing ARP request to be forwarded." );
    	  		}
    		}catch(Exception e){		
    	    	LOG.info( "TrafficManager: ArpPacketHandler: exception: {}",e );
    		}
        }
        else if(etherType == TYPE_8021X){
        	LOG.info("TrafficManager:PacketListener received package={}.", ofPacketIn);
        	try{
        	packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
			packetDataInputStream.skip(6 + 6 + 2 +1);
			type = packetDataInputStream.readByte();

      

        	  	if(type == 1){
            		OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
            		//0180c2000003
                	byte[] CDRIVES = hexStringToByteArray("0180c20000030800270741c7888e020000050101000501");
                	pktOut.data(CDRIVES);
                	pktOut.bufferId(ofPacketIn.getBufferId());
                	pktOut.inPort(Port.CONTROLLER);
                	pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, ofPacketIn.getInPort() ));
                	mControllerService.send(pktOut.toImmutable(), messageContext.srcEvent().dpid());
                	LOG.info( "TrafficManager:PacketListener event(): allowing EAPOL request to be forwarded" );
                	
            	}
        	  	if(type == 0){
        	  		packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
        	  		packetDataInputStream.skip(6);
        	  		byte[] mac_src = new byte[6];
        	  		packetDataInputStream.read(mac_src,0,6);
        	  		packetDataInputStream.skip(6);
        	  		byte code = packetDataInputStream.readByte();
        	  		if(code == 2){
        	  			//send radius message
        	  			packetDataInputStream.skip(1);//skip id
        	  			short len = packetDataInputStream.readShort();
            	  		byte code_type = packetDataInputStream.readByte();

            	  		if(code_type == (byte) 0x01){
            	  			byte[] user_id = new byte[len-5];
                	  		packetDataInputStream.read(user_id,0,len-5);
                	  		packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
                	  		packetDataInputStream.skip(18);
                	  		byte[] eap_msg = new byte[len];
                	  		packetDataInputStream.read(eap_msg, 0, len);
                	  		StatePacketHandler aux= new StatePacketHandler(mac_src,user_id,ofPacketIn.getInPort(),messageContext.srcEvent().dpid());
            	  			Conv_ID.add(aux);
							OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
	                    	byte[] header =build_Radius_header(Conv_ID.indexOf(aux));
	                    	byte[] radius_ptl = header;
	                    	radius_ptl =add_Radius_attr(1, user_id, radius_ptl);//user-name
	                    	//radius_ptl =add_Radius_attr(2, hexStringToByteArray("15b2ec9a8dcf3e08037384aac161a8b5"), radius_ptl);//password
	                    	//radius_ptl =add_Radius_attr(4, hexStringToByteArray("c0a8001c"), radius_ptl);//nas-ip
	                    	//radius_ptl =add_Radius_attr(5, hexStringToByteArray("0000007b"), radius_ptl);//nas-port
	                    	radius_ptl =add_Radius_attr(80, hexStringToByteArray("00000000000000000000000000000000"), radius_ptl);//message-auth
	                    	radius_ptl =add_Radius_attr(79, eap_msg, radius_ptl);//eap-msg
	                    	radius_ptl =build_Radius_msg_auth(radius_ptl);
	                		byte[] UDP_Header=build_Radius_UDP(IP_ADDR_CONT, RADIUS_IP, (short)radius_ptl.length);
	                		byte[] IPV4_Header=build_Radius_IPV4(IP_ADDR_CONT,RADIUS_IP, (short)(radius_ptl.length+8));
	                		byte[] Ethernet_Header = build_Ethernet_Header(MAC_ADDR_CONT,RADIUS_MAC,TYPE_IPv4);
	                    	byte[] radius_pkt = new byte[radius_ptl.length + UDP_Header.length + IPV4_Header.length + Ethernet_Header.length ];
	                    	System.arraycopy(Ethernet_Header, 0, radius_pkt, 0, Ethernet_Header.length);
	                    	System.arraycopy(IPV4_Header, 0, radius_pkt, Ethernet_Header.length, IPV4_Header.length);
	                    	System.arraycopy(UDP_Header, 0, radius_pkt, Ethernet_Header.length+IPV4_Header.length, UDP_Header.length);
	                    	System.arraycopy(radius_ptl, 0, radius_pkt, Ethernet_Header.length+IPV4_Header.length+UDP_Header.length, radius_ptl.length);
	        	  			pktOut.data(radius_pkt);
	                    	pktOut.bufferId(ofPacketIn.getBufferId());
	                    	pktOut.inPort(Port.CONTROLLER);
	                    	pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, RADIUS_SWI_PORT));
	                    	mControllerService.send(pktOut.toImmutable(), RADIUS_SWI);
	                    	LOG.info( "TrafficManager:PacketListener event(): allowing Radius first request to be forwarded" );
            	  		}else{// if((code_type == (byte) 0x04) || (code_type == (byte) 0x03)){
                	  		packetDataInputStream = new DataInputStream(new ByteArrayInputStream(ofPacketIn.getData()));
                	  		packetDataInputStream.skip(18);
                	  		byte[] eap_msg = new byte[len];
                	  		packetDataInputStream.read(eap_msg, 0, len);
							OfmMutablePacketOut pktOut = (OfmMutablePacketOut) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.PACKET_OUT);
							int pos=-1;
							for (StatePacketHandler temp : Conv_ID) {
								if(Arrays.equals(temp.getMac(),mac_src)){
									pos=Conv_ID.indexOf(temp);
								}
									
							}
							byte[] header =build_Radius_header(pos);
	                    	byte[] radius_ptl = header;
	                    	radius_ptl =add_Radius_attr(1, Conv_ID.get(pos).getUser(), radius_ptl);//user-name
	                    	//radius_ptl =add_Radius_attr(2, hexStringToByteArray("15b2ec9a8dcf3e08037384aac161a8b5"), radius_ptl);//password
	                    	//radius_ptl =add_Radius_attr(4, hexStringToByteArray("c0a8001c"), radius_ptl);//nas-ip
	                    	//radius_ptl =add_Radius_attr(5, hexStringToByteArray("0000007b"), radius_ptl);//nas-port
	                    	radius_ptl =add_Radius_attr(80, hexStringToByteArray("00000000000000000000000000000000"), radius_ptl);//message-auth
	                    	radius_ptl =add_Radius_attr(79, eap_msg, radius_ptl);//eap-msg
	                    	radius_ptl =add_Radius_attr(24, Conv_ID.get(pos).getState(), radius_ptl);
	                    	radius_ptl =build_Radius_msg_auth(radius_ptl);
	                		byte[] UDP_Header=build_Radius_UDP(IP_ADDR_CONT, RADIUS_IP, (short)radius_ptl.length);
	                		byte[] IPV4_Header=build_Radius_IPV4(IP_ADDR_CONT,RADIUS_IP, (short)(radius_ptl.length+8));
	                		byte[] Ethernet_Header = build_Ethernet_Header(MAC_ADDR_CONT,RADIUS_MAC,TYPE_IPv4);
	                    	byte[] radius_pkt = new byte[radius_ptl.length + UDP_Header.length + IPV4_Header.length + Ethernet_Header.length ];
	                    	System.arraycopy(Ethernet_Header, 0, radius_pkt, 0, Ethernet_Header.length);
	                    	System.arraycopy(IPV4_Header, 0, radius_pkt, Ethernet_Header.length, IPV4_Header.length);
	                    	System.arraycopy(UDP_Header, 0, radius_pkt, Ethernet_Header.length+IPV4_Header.length, UDP_Header.length);
	                    	System.arraycopy(radius_ptl, 0, radius_pkt, Ethernet_Header.length+IPV4_Header.length+UDP_Header.length, radius_ptl.length);
	        	  			pktOut.data(radius_pkt);
	                    	pktOut.bufferId(ofPacketIn.getBufferId());
	                    	pktOut.inPort(Port.CONTROLLER);
	                    	pktOut.addAction(ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, RADIUS_SWI_PORT ));
	                    	mControllerService.send(pktOut.toImmutable(), RADIUS_SWI);
	                    	LOG.info( "TrafficManager:PacketListener event(): allowing Radius second request to be forwarded" );
            	  		}
						

                    	
        	  		}
            	/*Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
            	messageContext.packetOut().addAction( action );
            	messageContext.packetOut().send();*/
        	  	}
    		}catch(Exception e){		
    	    	LOG.info( "TrafficManager:PacketListener 802.1x error: exception: {}",e );
    		}


            
        }
        else{
        	Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
        	messageContext.packetOut().addAction( action );
        	messageContext.packetOut().send();
        	LOG.info( "TrafficManager:PacketListener event(): packet_out sent." );

        }
	}
	
	public byte[] build_ARP_packet(DataInputStream packetDataInputStream, String macGateway) throws IOException {
		String[] mac_parts = macGateway.split(":");
		packetDataInputStream.skip(6);
		// convert hex string to byte values
		byte[] ARP_pkt = new byte[60];
		Integer hex;
		for(int i=0; i<6; i++){
		    ARP_pkt[i] = packetDataInputStream.readByte();
		}
		for(int i=6; i<12; i++){		
		    hex = Integer.parseInt(mac_parts[i-6], 16);
		    ARP_pkt[i] = hex.byteValue();
		}
		for(int i=12; i<21; i++){
		    ARP_pkt[i] = packetDataInputStream.readByte();
		}
		ARP_pkt[21]=(byte) 0x02;
		packetDataInputStream.skip(1);
		byte[] sender_mac_ip = new byte[10],target_ip= new byte[4];
		packetDataInputStream.read(sender_mac_ip,0,10);
		packetDataInputStream.skip(6);
		packetDataInputStream.read(target_ip,0,4);
		for(int i=22; i<28; i++){		
		    hex = Integer.parseInt(mac_parts[i-22], 16);
		    ARP_pkt[i] = hex.byteValue();
		}
		for(int i=28; i<32; i++){
		    ARP_pkt[i] = target_ip[i-28];
		}
		for(int i=32; i<42; i++){
		    ARP_pkt[i] = sender_mac_ip[i-32];
		}
		for(int i=42; i<60; i++){//padding
		    ARP_pkt[i] = (byte) 0x00;
		}
		return ARP_pkt;
	}

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static byte[] build_Radius_msg_auth(byte[] data) throws InvalidKeyException, IOException{
		try {
			SecretKeySpec key = new SecretKeySpec((shared).getBytes("UTF-8"),"HmacMD5");
			Mac mac = Mac.getInstance("HmacMD5");
		    mac.init(key);
		    byte[] bytes = mac.doFinal(data);
	    	DataInputStream packetDataInputStream = new DataInputStream(new ByteArrayInputStream(data));
	    	packetDataInputStream.skip(20);
	    	byte type,len;
	    	int pos=20;
	    	while(true){
	    		type=packetDataInputStream.readByte();
	    		if(type==0x50){
	    			break;
	    		}len=packetDataInputStream.readByte();
	    		packetDataInputStream.skip((long)(len-2)); 
	    		pos+=(int)len;
	    	}
	    	len=packetDataInputStream.readByte();
	    	pos+=2;
	    	for(int i=0;i<(int) (len-2);i++){
	    		data[pos+i]=bytes[i];
	    	}
		    return data;
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
	    	LOG.info( "TrafficManager:PacketListener Radius msg_auth error: exception: {}",e );
			return null;
		}

		
	}
	
	public static boolean check_Radius_auth(byte[] data, byte[] auth) throws NoSuchAlgorithmException{
		byte[] shared_b = shared.getBytes();
		byte[] auth_rad = new byte[16];
	    for(int i=0;i<16;i++){//46 skips headers
	    	auth_rad[i]=data[i+4];
	    	data[i+4]=auth[i];
	    }
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    byte[] data_key = new byte[data.length+shared_b.length];
		System.arraycopy(data, 0, data_key, 0, data.length);
    	System.arraycopy(shared_b, 0, data_key, data.length, shared_b.length);
        md.update(data_key);
        byte[] byteData = md.digest();
        if(Arrays.equals(auth_rad, byteData)){
        	LOG.info( "TrafficManager:PacketListener Radius check auth md5: {}", Hex.encodeHexString(byteData));
        	return true;
        }else{
        	LOG.info( "TrafficManager:PacketListener Radius incorrect auth md5.");
        	return false;
        }

		
	}
	
	public static byte[] build_Radius_header(int pos){
		Random rand= new Random();
		byte[] ident = new byte[1];
		byte[] auth = new byte[16];
		String Length = "0014";
		rand.nextBytes(ident);
        rand.nextBytes(auth);
		StatePacketHandler aux;
		aux = Conv_ID.get(pos); 
        aux.setAuth(auth);
        aux.setPacket_id(ident[0]);
		Conv_ID.set(pos, aux);
		byte[] data = hexStringToByteArray("01"+ Hex.encodeHexString(ident) + Length + Hex.encodeHexString(auth));

		return data;
	}
	
	public static byte[] add_Radius_attr(int type,byte[] attr_data, byte[] pkt) throws IOException{
		int len = attr_data.length;
    	LOG.info( "TrafficManager:PacketListener Radius check length_ini: {}", len);
		while(len>253){
	    	LOG.info( "TrafficManager:PacketListener Radius check length_while: {}", len);
			byte[] temp = new byte[253];
			for(int i=0;i<253;i++){
				temp[i]=attr_data[i];
			}
			pkt=add_Radius_attr(type, temp, pkt);
			len=len-253;
			byte[] temp_2 = new byte[len];
//			temp_2[0]=attr_data[0];
//			temp_2[1]=attr_data[1];
//			temp_2[2]=(byte) ((len >>> 8) & 0xFF);
//	    	temp_2[3] = (byte) (len & 0xFF);
			for(int i=0;i<len;i++){
				temp_2[i]=attr_data[i+253];
			}
			attr_data=temp_2;
			
		}
		len=len+2;
		byte[] attr_hd = {(byte) type,(byte) (len  & 0xFF)};
    	LOG.info( "TrafficManager:PacketListener Radius check length_fin: {}", len);
		byte[] attr = new byte[len];
		System.arraycopy(attr_hd, 0, attr, 0, attr_hd.length);
    	System.arraycopy(attr_data, 0, attr, attr_hd.length, attr_data.length);
    	DataInputStream packetDataInputStream = new DataInputStream(new ByteArrayInputStream(pkt));
    	packetDataInputStream.skip(2);
    	short Len = packetDataInputStream.readShort();
    	Len =(short) (Len + len);
    	pkt[2] = (byte) ((Len >>> 8) & 0xFF);
    	pkt[3] = (byte) (Len & 0xFF);
		byte[] pkt_fin = new byte[pkt.length+attr.length];
		System.arraycopy(pkt, 0, pkt_fin, 0, pkt.length);
    	System.arraycopy(attr, 0, pkt_fin, pkt.length, attr.length);
    	
		return pkt_fin;
	}
	
	public static byte[] build_Radius_UDP(String ip_src, String ip_dst, short Length) throws UnknownHostException{
		InetAddress ia = InetAddress.getByName(ip_src);
		byte[] src = ia.getAddress();
		ia = InetAddress.getByName(ip_dst);
		byte[] dst = ia.getAddress();
		byte[] check = new byte[12];
		int pos=0,i;
		for(i=0;i<4;i++){
			check[pos++]=src[i];
		}
		for(i=0;i<4;i++){
			check[pos++]=dst[i];
		}
		check[pos++]=0x00;
		check[pos++]=0x11;
		Length+=8;
		check[pos++]=(byte) ((Length >>> 8) & 0xFF);
    	check[pos] = (byte) (Length & 0xFF);
    	short checksum=0;
    	for(i=0;i<12;i=i+2){
    		checksum += ((check[i] & 0xFF) << 8) | (check[i+1] & 0xFF);
    	}
    	check = new byte[2];
    	check[0]=(byte) ((checksum >>> 8) & 0xFF);
    	check[1] = (byte) (checksum & 0xFF);
    	byte[] len = new byte[2];
    	len[0]=(byte) ((Length >>> 8) & 0xFF);
    	len[1] = (byte) (Length & 0xFF);
    	byte[] UDP_header= hexStringToByteArray("ffa3"+"0714"+Hex.encodeHexString(len)+ Hex.encodeHexString(check));
		
		
		
		return UDP_header;
	}
	
	public static byte[] build_Radius_IPV4(String ip_src, String ip_dst, short Length) throws UnknownHostException{
		InetAddress ia = InetAddress.getByName(ip_src);
		byte[] src = ia.getAddress();
		ia = InetAddress.getByName(ip_dst);
		byte[] dst = ia.getAddress();
		byte ptl = UDP;
		byte ver_ihl = 0x45;
		byte serv = 0x00;
		short len = (short) (Length+20);
		byte [] ident = new byte[2];
		Random rand= new Random();
		rand.nextBytes(ident);
		short flags_off = 0x0000;
		byte TTL = (byte) 0xff;
		byte[] IPV4_Header = new byte[20];
		
		IPV4_Header[0]=ver_ihl;
		IPV4_Header[1]= serv;
		IPV4_Header[2]=(byte) ((len >>> 8) & 0xFF);
    	IPV4_Header[3] = (byte) (len & 0xFF);
		IPV4_Header[4]= ident[0];
		IPV4_Header[5]= ident[1];
		IPV4_Header[6]=(byte) ((flags_off >>> 8) & 0xFF);
    	IPV4_Header[7] = (byte) (flags_off & 0xFF);
    	IPV4_Header[8]= TTL;
    	IPV4_Header[9]= ptl;
    	IPV4_Header[10]=0x00;//checksum
    	IPV4_Header[11]=0x00;//checksum
		int pos=12,i;
		for(i=0;i<4;i++){
			IPV4_Header[pos++]=src[i];
		}
		for(i=0;i<4;i++){
			IPV4_Header[pos++]=dst[i];
		}
    	int checksum=0;
    	for(i=0;i<20;i=i+2){
    		checksum += ((IPV4_Header[i] & 0xFF) << 8) | (IPV4_Header[i+1] & 0xFF);
    		if ((checksum & 0xFFFF0000) > 0) {
    	        checksum = checksum & 0xFFFF;
    	        checksum += 1;
    	      }
    	}
    	checksum = ~checksum;
        checksum = checksum & 0xFFFF;
		byte[] bytes = ByteBuffer.allocate(4).putInt(checksum).array();
		IPV4_Header[10]=bytes[2];
		IPV4_Header[11]=bytes[3];

	

		
		return IPV4_Header;
	}
	public static byte[] build_Ethernet_Header(String mac_src, String mac_dst, short Ether_type){
		String[] mac_src_parts = mac_src.split(":");
		String[] mac_dst_parts = mac_dst.split(":");

		// convert hex string to byte values
		byte[] Ethernet_Header = new byte[14];
		Integer hex;
		for(int i=0; i<6; i++){
		    hex = Integer.parseInt(mac_dst_parts[i], 16);
		    Ethernet_Header[i] = hex.byteValue();
		}
		for(int i=0; i<6; i++){
		    hex = Integer.parseInt(mac_src_parts[i], 16);
		    Ethernet_Header[i+6] = hex.byteValue();
		}
		Ethernet_Header[12]=(byte) ((Ether_type >>> 8) & 0xFF);
		Ethernet_Header[13] = (byte) (Ether_type & 0xFF);
		return Ethernet_Header;
	}
	
	public static void set_flows(int pos) throws IOException{
		BufferedReader br_profiles = new BufferedReader(new FileReader("//home//chuck//dev//sdn-apps//trafficmanager//tm-bl//profiles.txt"));
		BufferedReader br_users = new BufferedReader(new FileReader("//home//chuck//dev//sdn-apps//trafficmanager//tm-bl//users.txt"));
		String path = new File("").getAbsolutePath();
		SwitchListener aux_dpid = new SwitchListener();
		LOG.info( "TrafficManager:SwitchListener File path = {}", path);
		
		String sCurrentLine_users, sCurrentLine_profiles;
		byte[] user_bytes = Conv_ID.get(pos).getUser();
		String user = new String(user_bytes,"UTF-8"), prof= "1", service = null, action = null;
		IpAddress ip = null,mask=null;
		int num_devices=0;
		while ((sCurrentLine_users = br_users.readLine()) != null) {
			LOG.info( "TrafficManager:SwitchListener File_lines users = {}", sCurrentLine_users);
			String[] user_parts = sCurrentLine_users.split(" ");
			if(user_parts[0].equals(user)){
				num_devices= Integer.parseInt(user_parts[2]);
				for(int i=0;i<num_devices;i++){
					String[] mac_parts = user_parts[i+3].split(":");
					byte[] mac_aux = new byte[6];
					Integer hex;
					for(int j=0; j<6; j++){
					    hex = Integer.parseInt(mac_parts[j], 16);
					    mac_aux[j] = hex.byteValue();
					}
					LOG.info( "TrafficManager:SwitchListener mac = {} ;; user= {}", mac_aux, Conv_ID.get(pos).getMac());
					if(Arrays.equals(mac_aux ,Conv_ID.get(pos).getMac())){
						prof= user_parts[1];
						LOG.info( "TrafficManager:SwitchListener File_lines char = {}", prof);
					}
				}
				while ((sCurrentLine_profiles = br_profiles.readLine()) != null) {
					String[] parts = sCurrentLine_profiles.split(" ");
					if(prof.equals(parts[0])){
						LOG.info( "TrafficManager:SwitchListener File_lines profile = {}", sCurrentLine_profiles);
						ip= IpAddress.ip(parts[2]);
						mask= IpAddress.ip(parts[3]);
						service = parts[4];
						action = parts[5];
				    	for(int i=0;i<aux_dpid.get_num_switch();i++){
					    	OfmMutableFlowMod dst_FlowMod = (OfmMutableFlowMod)MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD , FlowModCommand.ADD);
					    	
					    	// Create the IP match and add it to the IP flow.
					    	IpProtocol test = null;
					    	if(service.equalsIgnoreCase("ICMP")){
					    		test = IpProtocol.ICMP;
					    	}else{
					    		test = IpProtocol.TCP;
					    	}
					    	MutableMatch dst_Match = MatchFactory.createMatch(  ProtocolVersion.V_1_3 )
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.IPV4_DST, ip,mask ))
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.IP_PROTO,test ))
									//.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ICMPV4_TYPE, ICMPv4Type.ECHO_REQ))
									.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_SRC, MacAddress.mac(Conv_ID.get(pos).getMac()))); 
					    	dst_FlowMod.cookie(COOKIE).tableId(TABLE_ID)
								.idleTimeout(FLOW_IDLE_TIMEOUT)
								.hardTimeout(FLOW_HARD_TIMEOUT)
								.flowModFlags(FLAGS)
								.match((Match) dst_Match.toImmutable());
					    	if(action.equalsIgnoreCase("NORMAL")){
					    		dst_FlowMod.priority(32000);
					    		for(Instruction ins2: createInstructions())
					    			dst_FlowMod.addInstruction(ins2);
					    	}else if(action.equalsIgnoreCase("DROP")){
				    			dst_FlowMod.priority(33000);
				    			for(Instruction ins2: createInstructions_drop())
				    				dst_FlowMod.addInstruction(ins2);
				    		}else{
				    			dst_FlowMod.priority(33000);
				    			for(Instruction ins2: createInstructions_drop2())
				    				dst_FlowMod.addInstruction(ins2);
				    		}
					    	
					    	// Now set this flow on the switch
					    	try{
					    		mControllerService.sendFlowMod( (OfmFlowMod)dst_FlowMod.toImmutable(), aux_dpid.get_Dpid(i) );
					    		LOG.info( "TrafficManager:PacketListener dst_flow successfully with switch = {}.",i);
					    	}
					    	catch( Exception e ) {
					    		LOG.info( "TrafficManager:PacketListener setFlows(): exception: {}", e );
					    		LOG.info( "TrafficManager:PacketListener setFlows(): exception: cause: {}", e.getCause() );
					    	}
					    	
					    	
					    	OfmMutableFlowMod src_FlowMod = (OfmMutableFlowMod)MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD , FlowModCommand.ADD);
					    	
					    	MutableMatch src_Match = MatchFactory.createMatch(  ProtocolVersion.V_1_3 )
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.IPV4_SRC, ip,mask ))
					    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.IP_PROTO,test ))
									//.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ICMPV4_TYPE, ICMPv4Type.ECHO_REQ))
									.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_DST, MacAddress.mac(Conv_ID.get(pos).getMac()))); 
					    	
					    	src_FlowMod.cookie(COOKIE).tableId(TABLE_ID)
								.idleTimeout(FLOW_IDLE_TIMEOUT)
								.hardTimeout(FLOW_HARD_TIMEOUT)
								.flowModFlags(FLAGS)
								.match((Match) src_Match.toImmutable());
					    	if(action.equalsIgnoreCase("NORMAL")){
					    		src_FlowMod.priority(32000);
					    		for(Instruction ins2: createInstructions())
					    			src_FlowMod.addInstruction(ins2);
					    	}else if(action.equalsIgnoreCase("DROP")){
					    			src_FlowMod.priority(33000);
					    			for(Instruction ins2: createInstructions_drop())
					    				src_FlowMod.addInstruction(ins2);
					    		}else{
					    			src_FlowMod.priority(33000);
					    			for(Instruction ins2: createInstructions_drop2())
					    				src_FlowMod.addInstruction(ins2);
					    		}
					    	
					    	// Now set this flow on the switch
					    	try{
					    		mControllerService.sendFlowMod( (OfmFlowMod)src_FlowMod.toImmutable(), aux_dpid.get_Dpid(i) );
					    		LOG.info( "TrafficManager:PacketListener dst_flow successfully with switch = {}.",i);
					    	}
					    	catch( Exception e ) {
					    		LOG.info( "TrafficManager:PacketListener setFlows(): exception: {}", e );
					    		LOG.info( "TrafficManager:PacketListener setFlows(): exception: cause: {}", e.getCause() );
					    	}
					    	
					    	
				    	}

					}
				}
				
			}
		}
		//LOG.info( "TrafficManager:SwitchListener User pos = {}", temp);
		//LOG.info( "TrafficManager:SwitchListener IP = {}", ip);
		//LOG.info( "TrafficManager:SwitchListener MASK = {}", mask);

	}
	
	private static List<Instruction> createInstructions(){
		List<Instruction> result = new ArrayList<Instruction>();
		//result.add(InstructionFactory.createInstruction(ProtocolVersion.V_1_3, InstructionType.WRITE_METADATA,INS_META_DATA, INS_META_MASK));
		InstrMutableAction apply = InstructionFactory.createMutableInstruction(ProtocolVersion.V_1_3,InstructionType.APPLY_ACTIONS);
		apply//.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT,Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
			.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL));
		result.add((Instruction) apply.toImmutable());
		return result;
	}
	
	private static List<Instruction> createInstructions_drop(){
		List<Instruction> result = new ArrayList<Instruction>();
		//result.add(InstructionFactory.createInstruction(ProtocolVersion.V_1_3, InstructionType.WRITE_METADATA,INS_META_DATA, INS_META_MASK));
		InstrMutableAction apply = InstructionFactory.createMutableInstruction(ProtocolVersion.V_1_3,InstructionType.APPLY_ACTIONS);
		apply//.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT,Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
			.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL));
		result.add((Instruction) apply.toImmutable());
		Instruction meter = InstructionFactory.createInstruction(ProtocolVersion.V_1_3,InstructionType.METER, MeterId.mid("1"));
		result.add(meter);
		return result;
	}
	
	private static List<Instruction> createInstructions_drop2(){
		List<Instruction> result = new ArrayList<Instruction>();
		//result.add(InstructionFactory.createInstruction(ProtocolVersion.V_1_3, InstructionType.WRITE_METADATA,INS_META_DATA, INS_META_MASK));
		InstrMutableAction apply = InstructionFactory.createMutableInstruction(ProtocolVersion.V_1_3,InstructionType.APPLY_ACTIONS);
		apply//.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT,Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
			.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL));
		result.add((Instruction) apply.toImmutable());
		Instruction meter = InstructionFactory.createInstruction(ProtocolVersion.V_1_3,InstructionType.METER, MeterId.mid("2"));
		result.add(meter);
		return result;
	}

}
