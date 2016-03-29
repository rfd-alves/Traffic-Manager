package com.fct.tm.handler;

import com.hp.of.lib.dt.DataPathId;
import com.hp.util.ip.BigPortNumber;

public class StatePacketHandler {
	private byte[] state;
	private byte[] mac;
	private byte[] user;
	private byte[] auth;
	private byte packet_id;
	private BigPortNumber port;
	private DataPathId dpid;
	
	public StatePacketHandler(byte[] mac, byte[] user, BigPortNumber port, DataPathId dpid) {
		this.mac = mac;
		this.user = user;
		this.state=null;
		this.auth = null;
		this.packet_id = 0x00;
		this.port= port;
		this.dpid= dpid;
	}

	public byte[] getState() {
		return state;
	}

	public void setState(byte[] state) {
		this.state = state;
	}

	public DataPathId getDpid() {
		return dpid;
	}

	public void setDpid(DataPathId dpid) {
		this.dpid = dpid;
	}

	public byte[] getMac() {
		return mac;
	}

	public BigPortNumber getPort() {
		return port;
	}

	public void setPort(BigPortNumber port) {
		this.port = port;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public byte[] getUser() {
		return user;
	}

	public void setUser(byte[] user) {
		this.user = user;
	}

	public byte[] getAuth() {
		return auth;
	}

	public void setAuth(byte[] auth) {
		this.auth = auth;
	}

	public byte getPacket_id() {
		return packet_id;
	}

	public void setPacket_id(byte packet_id) {
		this.packet_id = packet_id;
	}



}
