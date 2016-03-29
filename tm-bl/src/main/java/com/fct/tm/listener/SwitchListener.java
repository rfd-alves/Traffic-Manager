package com.fct.tm.listener;


import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.of.ctl.ControllerService;
import com.hp.of.ctl.DataPathEvent;
import com.hp.of.ctl.DataPathListener;
import com.hp.of.ctl.QueueEvent;
import com.hp.of.lib.OpenflowException;
import com.hp.of.lib.ProtocolVersion;
import com.hp.of.lib.dt.BufferId;
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
import com.hp.of.lib.msg.MeterBandFactory;
import com.hp.of.lib.msg.MeterBandType;
import com.hp.of.lib.msg.MeterFlag;
import com.hp.of.lib.msg.MeterModCommand;
import com.hp.of.lib.msg.OfmFlowMod;
import com.hp.of.lib.msg.OfmMeterMod;
import com.hp.of.lib.msg.OfmMutableFlowMod;
import com.hp.of.lib.msg.OfmMutableMeterMod;
import com.hp.of.lib.msg.Port;
import com.hp.util.ip.BigPortNumber;
import com.hp.util.ip.EthernetType;
import com.hp.util.ip.IpAddress;
import com.hp.util.ip.IpProtocol;
import com.hp.util.ip.MacAddress;
import com.hp.util.ip.PortNumber;

public class SwitchListener implements DataPathListener{

	private volatile ControllerService mControllerService;
	private static final Logger LOG = LoggerFactory.getLogger(SwitchListener.class);
	private static final ProtocolVersion PV = ProtocolVersion.V_1_3;
	private static final long COOKIE = 0x00002468;
	private static final TableId TABLE_ID = TableId.valueOf(100);
	private static final int FLOW_IDLE_TIMEOUT = 0;
    private static List<DataPathId> Dpids = new ArrayList<DataPathId>();
	private static final int FLOW_HARD_TIMEOUT = 0;
	private static final Set<FlowModFlag> FLAGS = EnumSet.of(
			FlowModFlag.SEND_FLOW_REM,
			FlowModFlag.CHECK_OVERLAP,
			FlowModFlag.NO_BYTE_COUNTS
	);
	private static final Set<MeterFlag> METER_FLAGS = EnumSet.of(
			MeterFlag.KBPS
	);
	private static final MacAddress MAC = MacAddress.valueOf("00001e:000000");
	private static final MacAddress MAC_MASK = MacAddress.valueOf("ffffff:000000");
	private static final PortNumber SMTP_PORT = PortNumber.valueOf(53);
	private static final PortNumber RADIUS_PORT = PortNumber.valueOf(1812);

	
	public void init(final ControllerService controllerService ){
		LOG.info("TrafficManager:SwitchListener Initiated!!!");
		mControllerService = controllerService;
	}
	
	public void startUp(){
		mControllerService.addDataPathListener(this);
		LOG.info("TrafficManager:SwitchListener Started!!!");
	}
	
	public void shutDown(){
		mControllerService.removeDataPathListener(this);
		LOG.info("TrafficManager:SwitchListener Finished!!!");
	}

	@Override
	public void event(DataPathEvent dpEvent) {
		
		switch( dpEvent.type() ) {
		
		case DATAPATH_CONNECTED:
			LOG.info( "TrafficManager:SwitchListener event(): Received datapath-connected event." );
			//setInitialFlows2(dpEvent.dpid());
			break;
			
		case DATAPATH_DISCONNECTED:
			LOG.info( "TrafficManager:SwitchListener event(): Received datapath-disconnected event." );
			break;
			
		case DATAPATH_READY:
			LOG.info( "TrafficManager:SwitchListener event(): Received datapath-ready event." );
			setInitialFlows(dpEvent.dpid());
			break;
		default:
			LOG.info( "TrafficManager:SwitchListener event(): Received some other datapath event= {}.", dpEvent.type() );
			break;			
			
		}
		
	}

	@Override
	public void queueEvent(QueueEvent arg0) {
		// TODO Auto-generated method stub
		LOG.info("TrafficManager:ola5");

		
	}
	
	private void setInitialFlows(DataPathId dpId){
		Dpids.add(dpId);

		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): dpid={}", dpId );
		
    	// Create an OF flow mod message for our any flow.
    	OfmMutableFlowMod anyFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.DELETE );
    	
    	// Create the ARP match and add it to the ARP flow.
    	MutableMatch anyMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 );
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.valueOf(34958) ));
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.SNMP ));
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));

    	
    	anyFlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(0)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) anyMatch.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
//    	arpFlowMod.command( FlowModCommand.ADD )
//    			  .hardTimeout(0)
//    			  .idleTimeout(0)
//    			  .priority( 40000 )
//      			  .bufferId( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	for(Instruction ins3: createInstructions())
    		anyFlowMod.addInstruction(ins3);
    	try{
    		//mControllerService.sendFlowMod( (OfmFlowMod)anyFlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", anyFlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
    	}

    	OfmMutableFlowMod radius_src_FlowMod = (OfmMutableFlowMod)MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD , FlowModCommand.ADD);
    	// Create the DNS match and add it to the DNS flow.
    	/*MutableMatch dnsMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP ))
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.UDP_DST,  PortNumber.valueOf(53) ));
    	dnsFlowMod.match( (Match)dnsMatch.toImmutable() );*/
    	
    	MutableMatch radius_src_mm = MatchFactory.createMatch(PV)
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_SRC, MAC, MAC_MASK))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP))
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, SMTP_PORT))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_SRC, RADIUS_PORT));

    	
    	radius_src_FlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(33000)
    				.idleTimeout(FLOW_IDLE_TIMEOUT)
    				.hardTimeout(FLOW_HARD_TIMEOUT)
    				//.flowModFlags(FLAGS)
    				.match((Match) radius_src_mm.toImmutable());
    	
    	// Create the forward-to-controller action and add it to the DNS flow.
    	for(Instruction ins: createInstructions())
    		radius_src_FlowMod.addInstruction(ins);
    	//Action dnsAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER );
    	//dnsFlowMod.addAction( dnsAction );

    	// Add the other fields for the flow mod message.
    	/*dnsFlowMod.command( FlowModCommand.ADD )
    			  .hardTimeout(0)
    			  .idleTimeout(0)
    			  .priority( 40000 )
    			  .bufferId( BufferId.NO_BUFFER );*/

    	// Send the flow modification message to the switch
    	try{
        	mControllerService.sendFlowMod( (OfmFlowMod)radius_src_FlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully dns= {}.", radius_src_FlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows() dns exception: {}", e );
    	}
    	
    	OfmMutableFlowMod radius_dst_FlowMod = (OfmMutableFlowMod)MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD , FlowModCommand.ADD);
    	// Create the DNS match and add it to the DNS flow.
    	/*MutableMatch dnsMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP ))
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.UDP_DST,  PortNumber.valueOf(53) ));
    	dnsFlowMod.match( (Match)dnsMatch.toImmutable() );*/
    	
    	MutableMatch radius_dst_mm = MatchFactory.createMatch(PV)
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_SRC, MAC, MAC_MASK))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.IP_PROTO, IpProtocol.UDP))
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, SMTP_PORT))
				.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.UDP_DST, RADIUS_PORT));

    	
    	radius_dst_FlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(33000)
    				.idleTimeout(FLOW_IDLE_TIMEOUT)
    				.hardTimeout(FLOW_HARD_TIMEOUT)
    				//.flowModFlags(FLAGS)
    				.match((Match) radius_dst_mm.toImmutable());
    	
    	// Create the forward-to-controller action and add it to the DNS flow.
    	for(Instruction ins20: createInstructions())
    		radius_dst_FlowMod.addInstruction(ins20);
    	//Action dnsAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER );
    	//dnsFlowMod.addAction( dnsAction );

    	// Add the other fields for the flow mod message.
    	/*dnsFlowMod.command( FlowModCommand.ADD )
    			  .hardTimeout(0)
    			  .idleTimeout(0)
    			  .priority( 40000 )
    			  .bufferId( BufferId.NO_BUFFER );*/

    	// Send the flow modification message to the switch
    	try{
        	mControllerService.sendFlowMod( (OfmFlowMod)radius_dst_FlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully dns= {}.", radius_dst_FlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows() dns exception: {}", e );
    	}

//    	OfmMutableFlowMod ipFlowMod = (OfmMutableFlowMod)MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD , FlowModCommand.ADD);
//    	
//    	// Create the IP match and add it to the IP flow.
//    	MutableMatch ipMatch = MatchFactory.createMatch(  ProtocolVersion.V_1_3 )
//    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ));
//    	
//    	ipFlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(32000)
//			.idleTimeout(FLOW_IDLE_TIMEOUT)
//			.hardTimeout(FLOW_HARD_TIMEOUT)
//			.flowModFlags(FLAGS)
//			.match((Match) ipMatch.toImmutable());
//    	// Create the forward-to-controller action and add it to the IP flow.
//    	//Action ipAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER );
//    	//ipFlowMod.addAction( ipAction );
//    	
//    	// Add the other fields for the flow mod message.
//    	/*ipFlowMod.command( FlowModCommand.ADD )
//    		  	 .hardTimeout(0)
//    		  	 .idleTimeout(0)
//    		  	 .priority( 30000 )
//		         .bufferId( BufferId.NO_BUFFER );*/
//    	for(Instruction ins1: createInstructions_arp())
//    		ipFlowMod.addInstruction(ins1);
//    	
//    	// Now set this flow on the switch
//    	try{
//			mControllerService.sendFlowMod( (OfmFlowMod)ipFlowMod.toImmutable(), dpId );
//    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully ip." );
//    	}
//    	catch( Exception e ) {
//    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): ip exception: {}", e );
//    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): ip exception: cause: {}", e.getCause() );
//    	}
    	
    	// Create an OF flow mod message for our ARP flow.
    	OfmMutableFlowMod arpFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.ADD );
    	
    	// Create the ARP match and add it to the ARP flow.
    	MutableMatch arpMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			.addField( FieldFactory.createBasicField( ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.ARP ));
    	
    	arpFlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(33000)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) arpMatch.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
    	/*arpFlowMod.command( FlowModCommand.ADD )
    			  .hardTimeout(0)
    			  .idleTimeout(0)
    			  .priority( 40000 )
      			  .bufferId( BufferId.NO_BUFFER );*/
    	
    	// Now set this flow on the switch
    	for(Instruction ins2: createInstructions())
    		arpFlowMod.addInstruction(ins2);
    	try{
    		mControllerService.sendFlowMod( (OfmFlowMod)arpFlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully arp." );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): arp exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): arp exception: cause: {}", e.getCause() );
    	}
    	
    	
    	// Create an OF flow mod message for our any flow.
    	anyFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.DELETE );
    	
    	// Create the ARP match and add it to the ARP flow.
    	anyMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 );
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.valueOf(34958) ));
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.SNMP ));
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));

    	
    	anyFlowMod.cookie(COOKIE).tableId(TableId.valueOf(200)).priority(0)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) anyMatch.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
//    	arpFlowMod.command( FlowModCommand.ADD )
//    			  .hardTimeout(0)
//    			  .idleTimeout(0)
//    			  .priority( 40000 )
//      			  .bufferId( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	for(Instruction ins3: createInstructions())
    		anyFlowMod.addInstruction(ins3);
    	try{
    		//mControllerService.sendFlowMod( (OfmFlowMod)anyFlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", anyFlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
    	}
    	
    	// Create an OF flow mod message for our any flow.
    	anyFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.DELETE );
    	
    	// Create the ARP match and add it to the ARP flow.
    	anyMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 );
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.valueOf(34958) ));
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.SNMP ));
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));

    	
    	anyFlowMod.cookie(COOKIE).tableId(TableId.valueOf(0)).priority(0)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) anyMatch.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
//    	arpFlowMod.command( FlowModCommand.ADD )
//    			  .hardTimeout(0)
//    			  .idleTimeout(0)
//    			  .priority( 40000 )
//      			  .bufferId( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	for(Instruction ins3: createInstructions())
    		anyFlowMod.addInstruction(ins3);
    	try{
    		//mControllerService.sendFlowMod( (OfmFlowMod)anyFlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", anyFlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
    	}
    	
    	// Create an OF flow mod message for our any flow.
    	OfmMutableFlowMod eapFlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.ADD );
    	
    	// Create the ARP match and add it to the ARP flow.
    	MutableMatch eapMatch = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.valueOf(34958) ));
				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.SNMP ));
    			.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));

    	
    	eapFlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(33000)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) eapMatch.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
//    	arpFlowMod.command( FlowModCommand.ADD )
//    			  .hardTimeout(0)
//    			  .idleTimeout(0)
//    			  .priority( 40000 )
//      			  .bufferId( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	for(Instruction ins4: createInstructions())
    		eapFlowMod.addInstruction(ins4);
    	try{
    		mControllerService.sendFlowMod( (OfmFlowMod)eapFlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", eapFlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
    	}
    	
//    	// Create an OF flow mod message for our any flow.
//    	OfmMutableFlowMod eap2FlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.ADD );
//    	
//    	// Create the ARP match and add it to the ARP flow.
//    	MutableMatch eap2Match = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
//    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.valueOf(34958) ));
//				//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_TYPE,EthernetType.SNMP ));
//    			.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));
//
//    	
//    	eap2FlowMod.cookie(COOKIE).tableId(TableId.valueOf(200)).priority(33000)
//			.idleTimeout(FLOW_IDLE_TIMEOUT)
//			.hardTimeout(FLOW_HARD_TIMEOUT)
//			//.flowModFlags(FLAGS)
//			.match((Match) eap2Match.toImmutable());
//    	// Create the forward-to-controller action and add it to the IP flow.
//    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
//    	//arpFlowMod.addAction( arpAction );
//    	
//    	// Add the other fields for the flow mod message.
////    	arpFlowMod.command( FlowModCommand.ADD )
////    			  .hardTimeout(0)
////    			  .idleTimeout(0)
////    			  .priority( 40000 )
////      			  .bufferId( BufferId.NO_BUFFER );
//    	
//    	// Now set this flow on the switch
//    	for(Instruction ins5: createInstructions())
//    		eap2FlowMod.addInstruction(ins5);
//    	try{
//    		mControllerService.sendFlowMod( (OfmFlowMod)eap2FlowMod.toImmutable(), dpId );
//    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", eap2FlowMod.getMatch() );
//    	}
//    	catch( Exception e ) {
//    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
//    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
//    	}
    	
    	OfmMutableMeterMod m = (OfmMutableMeterMod) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.METER_MOD, MeterModCommand.ADD);
        m.meterId(MeterId.mid("1"))
        	//.addBand(MeterBandFactory.createBand(ProtocolVersion.V_1_3, MeterBandType.DROP, 1073741824, 2048 ))
        	.addBand(MeterBandFactory.createBand(ProtocolVersion.V_1_3, MeterBandType.DROP, 5000, 1 ))//30Mbit rate
        	.meterFlags(METER_FLAGS);
        try {
			mControllerService.sendMeterMod((OfmMeterMod) m.toImmutable(), dpId );
			LOG.info( "TrafficManager:SwitchListener set meter mod successfully.");
		} catch (OpenflowException e) {
			LOG.info( "TrafficManager:SwitchListener setMeterMod(): any exception: {}", e );
			LOG.info( "TrafficManager:SwitchListener setMeterMod(): any exception: cause: {}", e.getCause() );
		}
        
        OfmMutableMeterMod m2 = (OfmMutableMeterMod) MessageFactory.create(ProtocolVersion.V_1_3, MessageType.METER_MOD, MeterModCommand.ADD);
        m2.meterId(MeterId.mid("2"))
        	//.addBand(MeterBandFactory.createBand(ProtocolVersion.V_1_3, MeterBandType.DROP, 1073741824, 2048 ))
        	.addBand(MeterBandFactory.createBand(ProtocolVersion.V_1_3, MeterBandType.DROP, 12000, 1 ))//30Mbit rate
        	.meterFlags(METER_FLAGS);
        try {
			mControllerService.sendMeterMod((OfmMeterMod) m2.toImmutable(), dpId );
			LOG.info( "TrafficManager:SwitchListener set meter mod successfully.");
		} catch (OpenflowException e) {
			LOG.info( "TrafficManager:SwitchListener setMeterMod(): any exception: {}", e );
			LOG.info( "TrafficManager:SwitchListener setMeterMod(): any exception: cause: {}", e.getCause() );
		}
        
    	OfmMutableFlowMod any2FlowMod = (OfmMutableFlowMod) MessageFactory.create( ProtocolVersion.V_1_3, MessageType.FLOW_MOD, FlowModCommand.ADD );
    	
    	// Create the ARP match and add it to the ARP flow.
    	MutableMatch any2Match = MatchFactory.createMatch( ProtocolVersion.V_1_3 )
    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.ETH_TYPE, EthernetType.IPv4 ))
    			.addField(FieldFactory.createBasicField(ProtocolVersion.V_1_3, OxmBasicFieldType.IP_PROTO,IpProtocol.ICMP ));
    			//.addField(FieldFactory.createBasicField(PV, OxmBasicFieldType.ETH_DST, MacAddress.mac("01:80:c2:00:00:03")));

    	
    	any2FlowMod.cookie(COOKIE).tableId(TABLE_ID).priority(33000)
			.idleTimeout(FLOW_IDLE_TIMEOUT)
			.hardTimeout(FLOW_HARD_TIMEOUT)
			//.flowModFlags(FLAGS)
			.match((Match) any2Match.toImmutable());
    	// Create the forward-to-controller action and add it to the IP flow.
    	//Action arpAction = ActionFactory.createAction( ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL  );
    	//arpFlowMod.addAction( arpAction );
    	
    	// Add the other fields for the flow mod message.
//    	arpFlowMod.command( FlowModCommand.ADD )
//    			  .hardTimeout(0)
//    			  .idleTimeout(0)
//    			  .priority( 40000 )
//      			  .bufferId( BufferId.NO_BUFFER );
    	
    	// Now set this flow on the switch
    	for(Instruction ins30: createInstructions())
    		any2FlowMod.addInstruction(ins30);
    	try{
    		//mControllerService.sendFlowMod( (OfmFlowMod)any2FlowMod.toImmutable(), dpId );
    		LOG.info( "TrafficManager:SwitchListener set initial flows successfully any match= {}.", any2FlowMod.getMatch() );
    	}
    	catch( Exception e ) {
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: {}", e );
    		LOG.info( "TrafficManager:SwitchListener setInitialFlows(): any exception: cause: {}", e.getCause() );
    	}
    	
    	
	}
	

	private static final long INS_META_MASK = 0xffff0000;
	private static final long INS_META_DATA = 0x33ab0000;

	private List<Instruction> createInstructions(){
		List<Instruction> result = new ArrayList<Instruction>();
		//result.add(InstructionFactory.createInstruction(ProtocolVersion.V_1_3, InstructionType.WRITE_METADATA,INS_META_DATA, INS_META_MASK));
		InstrMutableAction apply = InstructionFactory.createMutableInstruction(ProtocolVersion.V_1_3,InstructionType.APPLY_ACTIONS);
		apply.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT,Port.CONTROLLER, ActOutput.CONTROLLER_NO_BUFFER));
			//.addAction(ActionFactory.createAction(ProtocolVersion.V_1_3, ActionType.OUTPUT, Port.NORMAL));
		result.add((Instruction) apply.toImmutable());
		return result;
	}
	
	private List<Instruction> createInstructions_meter(){
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
	
	public DataPathId get_Dpid(int index){
		return Dpids.get(index);
	}
	
	public int get_num_switch(){
		return Dpids.size();
	}
}
