/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package lib;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.SecretKey;


public class Message implements Serializable{

	private static final long serialVersionUID = 1L;

	private Commands type;
	private String m;
	private String groupAtual;
	private int nWall;
	private int keyId;
	private long nonce;
	private List<String> followers;
	private List<PhotoInfo> wallPhotos;
	private List<String> own;
	private List<String> member;
	private List<String> group;
	private List<Entry<String, SecretKey>> novasChavesOuMensagensCifradas;
	private List<Entry<String, String>> listUsersCerts;
	private byte[] signature;
	private byte[] postPhotoBytes;
	private SecretKey wrappedKey;
	private Certificate cert;
	
	
	

	public Message(Commands t) {

		this.type = t;
	}	
	

	public Message(Commands t, String s) {
		this.type = t;
		
		if (t == Commands.CHAVE) {
			this.groupAtual = s;
		}
		else {
			m = s;
		}
		
	}
	

	public Message(Commands photo, byte[] imagebytes, String extension) {
		this.type = photo;
		postPhotoBytes = imagebytes;
		m = extension;
	}
	

	@SuppressWarnings("unchecked")
	public Message(Commands type, List<?> list) {
		this.type = type;

		if (type == Commands.VIEWFOLLOWERS) 
			this.followers = (List<String>) list;

		else if (type == Commands.COLLECT || type == Commands.HISTORY || type == Commands.REMOVEU || type == Commands.ADDU)
			this.novasChavesOuMensagensCifradas = (List<Entry<String, SecretKey>>) list;
		
		else if(type == Commands.OK)
			this.listUsersCerts = (List<Entry<String, String>>) list;
	}

	public Message(Commands type, int num) {
		
		this.type = type;
		this.nWall = num;

	}

	public Message(Commands ginfo, List<String> owner, List<String> member, List<String> group) {
		this.type = ginfo;
		this.own = owner;
		this.member = member;
		this.group = group;
	}

	public Message(Commands wall, int nWall, List<PhotoInfo> sendingPhotos) {
		this.type = wall;
		this.nWall = nWall;
		this.wallPhotos = sendingPhotos;
	}
	
	public Message(Commands t, long n) {
		this.type = t;
		nonce = n ;
	}
	
	public Message(Commands authentication, byte[] nonce2) {
		this.type = authentication;
		signature = nonce2 ;
	}

	public Message(Commands authentication, long nonce, byte[] sig, Certificate c) {
		this.type = authentication;
		this.nonce = nonce;
		signature = sig ;
		cert = c;
	}
	
	public Message(Commands newgroup, String s, SecretKey wrappedKey) {
		this.type = newgroup;
		this.m = s;
		this.wrappedKey = wrappedKey;
	}


	public Message(Commands msg, String cifrada, String grupo, int value) {
		this.type = msg;
		this.m = cifrada;
		this.keyId = value;
		this.groupAtual = grupo;
	}

	public Message(Commands chave, SecretKey wrapClientKey, int lastID) {
		this.type = chave;
		this.wrappedKey = wrapClientKey;
		this.keyId = lastID;
	}

	public Certificate getCertificate() {
		return cert;
	}
	
	public long getNonce() {
		return nonce;
	}
	
	public byte[] getSignature() {
		return signature;
	}

	public String getMessage() {

		return m;
	}

	public Commands getType() {

		return type;
	}

	public byte[] getPostPhoto() {

		return postPhotoBytes;
	}

	public int getWallN() {
		return nWall;
	}

	public List<PhotoInfo> getWallPhotos() {
		return wallPhotos;
	}

	public List<String> getFollowers() {

		return followers;
	}

	public List<String> getOwnGroups() {

		return own;
	}

	public List<String> getGroups() {
		return member;
	}

	public List<String> getGroupInfo() {

		return group;
	}

	public SecretKey getWrappedKey() {
		return wrappedKey;
	}

	public Integer getKeyId() {
		return keyId;
	}

	public String getGrupoAtual() {
		return groupAtual;
	}

	public List<Map.Entry<String, String>> getListaNomesCert() {
		return listUsersCerts;
	}
	
	public List<Entry<String, SecretKey>> getMensagesCifradasOuNovasChaves() {
		return novasChavesOuMensagensCifradas;
		
	}
}
