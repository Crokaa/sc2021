/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package lib;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.crypto.SecretKey;
import java.io.Serializable;

public class Group implements Serializable {

	private static final long serialVersionUID = 1L;

	private String id;
	private String owner;
	private ArrayList<String> clientes;
	private ArrayList<Integer> toReadMessages;
	private ArrayList<Integer> enteredAtMessage;
	private ArrayList<Map<String, SecretKey>> userId_newGroupKeysList;
	int historyPointer;
	private ArrayList<Entry<Integer, String>> messages;

	public Group(String id, String username_client, SecretKey firstKey){

		this.id = id;
		historyPointer = 0;

		clientes = new ArrayList<>();
		toReadMessages = new ArrayList<>();
		enteredAtMessage = new ArrayList<>();
		userId_newGroupKeysList = new ArrayList<>();

		clientes.add(username_client);
		toReadMessages.add(0);
		enteredAtMessage.add(0);

		owner = username_client;

		Map<String, SecretKey> userId_newGroupKeys = new HashMap<>();
		userId_newGroupKeys.put(username_client, firstKey);
		userId_newGroupKeysList.add(userId_newGroupKeys);

		messages = new ArrayList<>();
	}


	public void add(String username_client, List<Entry<String, SecretKey>> ls) {

		clientes.add(username_client);
		toReadMessages.add(0);
		enteredAtMessage.add(messages.size());

		Map<String, SecretKey> testeCriar = new HashMap<>();

		for (Entry<String, SecretKey> entry : ls) {
			testeCriar.put(entry.getKey(), entry.getValue());
		}

		userId_newGroupKeysList.add(testeCriar);
	}


	public void remove(String username_client, List<Entry<String, SecretKey>> ls) {

		int i = clientes.indexOf(username_client);
		clientes.remove(username_client);
		toReadMessages.remove(i);
		enteredAtMessage.remove(i);

		for (Map<String, SecretKey> m : userId_newGroupKeysList) {
			m.remove(username_client);
		}

		Map<String, SecretKey> testeCriar = new HashMap<>();

		for (Entry<String, SecretKey> entry : ls) {
			testeCriar.put(entry.getKey(), entry.getValue());
		}

		userId_newGroupKeysList.add(testeCriar);
	}


	public List<String> getInfo(){

		ArrayList<String> clientes_aux = new ArrayList<>();

		for(String client : clientes)
			clientes_aux.add(client);

		return clientes_aux;
	}


	public void sendMessage(String message, int idChave) {

		messages.add(new AbstractMap.SimpleEntry<>(idChave, message));

		for(int i = 0; i < toReadMessages.size(); i++) {
			toReadMessages.set(i, toReadMessages.get(i) + 1);
		}
	}


	public List<Entry<String, SecretKey>> collect(String username_client) {

		ArrayList<Entry<String, SecretKey>> collMsgs = new ArrayList<>();
		int index = clientes.indexOf(username_client);
		int nrMsgs = toReadMessages.get(index);


		if(nrMsgs > 0) {
			for(int i = messages.size() - nrMsgs; i < messages.size(); i++) {

				String msgCifrada = messages.get(i).getValue();
				SecretKey wrapEspecifico = userId_newGroupKeysList.get(messages.get(i).getKey()).get(username_client);

				collMsgs.add(new AbstractMap.SimpleEntry<>(msgCifrada, wrapEspecifico));

				toReadMessages.set(index, toReadMessages.get(index) - 1);
			}

			checkAllReceived();
			return collMsgs;
		}

		return collMsgs;
	}


	//verifica se todos ja receberam uma mensagem com messages.size() - nrMaxMsgsToRead
	private void checkAllReceived() {

		int nrMaxMsgsToRead = maxMsgsToRead();
		for(int i = historyPointer; i < messages.size() - nrMaxMsgsToRead; i++) {
			addToHistory();
		}			
	}


	//devolve o numero maximo de mensagens por receber
	private int maxMsgsToRead() {

		int max = 0;
		for(int i = 0; i < toReadMessages.size(); i++)
			if(toReadMessages.get(i) > max)
				max = toReadMessages.get(i);
		return max;
	}


	private void addToHistory() {
		historyPointer++;
	}


	public List<Entry<String, SecretKey>> getFromHistory(String username_client) {

		int index = clientes.indexOf(username_client);
		int enteredWhen = enteredAtMessage.get(index);
		ArrayList<Entry<String, SecretKey>> client_history = new ArrayList<>();

		for(int i = enteredWhen; i < messages.size() - toReadMessages.get(index); i++) {

			String msgCifrada = messages.get(i).getValue();
			SecretKey wrapEspecifico = userId_newGroupKeysList.get(messages.get(i).getKey()).get(username_client);

			client_history.add(new AbstractMap.SimpleEntry<>(msgCifrada, wrapEspecifico));
		}

		return ( client_history.size() > 0 ? client_history : null);
	}


	public String getOwner() {
		return owner;
	}


	public boolean isMember(String user) {
		return clientes.contains(user);
	}


	public List<String> members() {
		return clientes;
	}


	public SecretKey getWrapKey(String username) {
		return userId_newGroupKeysList.get(this.getLastId()).get(username);
	}


	public int getLastId() {
		return (userId_newGroupKeysList.size()-1);
	}


	public String groupOwner() {
		return owner;
	}


	public String getId() {
		return id;
	}
}
