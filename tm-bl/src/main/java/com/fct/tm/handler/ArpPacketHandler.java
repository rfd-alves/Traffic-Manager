package com.fct.tm.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.of.ctl.pkt.MessageContext;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.instr.Action;
import com.hp.of.lib.instr.ActionFactory;
import com.hp.of.lib.instr.ActionType;
import com.hp.of.lib.msg.OfmPacketIn;
import com.hp.of.lib.msg.Port;

public class ArpPacketHandler {
	private static final Logger LOG = LoggerFactory.getLogger( DnsPacketHandler.class );

	//-----------------------------------------------------------------------------------
	public boolean handle( MessageContext messageContext, OfmPacketIn ofPacketIn )
	{
		// Determine if the DNS request is okay or not, using ofPacketIn
		
		// If the DNS request is okay, set an action to forward it
		try{
    	Action action = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL );
    	messageContext.packetOut().addAction( action );  	
		}catch(Exception e){		
	    	LOG.info( "TrafficManager: ArpPacketHandler: exception: {}",e );
		}
    	
    	return true;

	}
}
