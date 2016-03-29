package com.fct.tm.handler;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.BufferId;
import com.hp.of.lib.instr.Action;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.match.FieldFactory;
import com.hp.of.lib.match.Match;
import com.hp.of.lib.match.MatchFactory;
import com.hp.of.lib.match.MutableMatch;
import com.hp.of.lib.match.OxmBasicFieldType;
import com.hp.of.lib.msg.FlowModCommand;
import com.hp.of.lib.msg.MessageFactory;
import com.hp.of.lib.msg.MessageType;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.of.lib.msg.Port;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.pkt.Ip;
import com.hp.util.pkt.Packet;
import com.hp.util.pkt.ProtocolId;

public class IpPacketHandler {
ControllerService mControllerService;
	
	private static final Logger LOG = LoggerFactory.getLogger( IpPacketHandler.class );

	//-----------------------------------------------------------------------------------
    public IpPacketHandler( ControllerService controllerService )
    {
    	mControllerService = controllerService;
    }
    
	//-----------------------------------------------------------------------------------
	public boolean handle( MessageContext messageContext, Packet packetInData )
	{
		// Determine if the IP destination address is okay or not, using ofPacketIn

		// Extract the destination IP address from the packet data.
		Ip      ipData        = packetInData.get(ProtocolId.IP);
	
		IpAddress destIpAddress = ipData.dstAddr();
		LOG.info("TrafficManager:ola6");
		// If the IP destination address is okay, set an action to forward it
    	Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
		LOG.info("TrafficManager:ola7");

    	messageContext.packetOut().addAction( action );
		LOG.info("TrafficManager:ola8");

    	LOG.info( "TrafficManager: IpPacketHandler: handle(): adding action NORMAL to packet-out" );
    	
    	setDestinationIpFlow( messageContext, destIpAddress );
		LOG.info("TrafficManager:ola9");

    	return true;
	}
	
	//-----------------------------------------------------------------------------------
	private void setDestinationIpFlow( MessageContext messageContext, IpAddress destIpAddress )
	{
    	// Create an OF flow mod message for our initial IP destination address flow.
    	OfmMutableFlowMod ipDestAllowFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD );
    	
    	// Create the IP destination address match and add it to the flow.
    	MutableMatch match = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.IPV4_DST, destIpAddress ));
    	  	 	
    	ipDestAllowFlowMod.match( (Match)match.toImmutable() );
    	
    	// Create the forward-normal action and add it to the flow.
    	Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	ipDestAllowFlowMod.addAction( action );
    	
    	// Add the other fields for the flow mod message.
    	ipDestAllowFlowMod.command( FlowModCommand.ADD )
    			  .hardTimeout( 0 )
    			  .idleTimeout( 60 )
    			  .priority   ( 39000 )
    			  .bufferId   ( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	try{
    		LOG.info( "TrafficManager: IpPacketHandler: setDestinationIpFlow(): setting flow: {}", ipDestAllowFlowMod );
        	mControllerService.sendFlowMod( (OfmFlowMod)ipDestAllowFlowMod.toImmutable(), messageContext.srcEvent().dpid() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager: IpPacketHandler: setDestinationIpFlow(): exception: {}", e );
    	}

	}

}
