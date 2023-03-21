/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import lib.Client;
import lib.Commands;
import lib.Group;
import lib.Message;
import lib.PhotoInfo;
import lib.SeiTchizPhoto;

public class SeiTchizServer {

	private static final String USER_LOGINS_TXT_LOCATION = "userLogins.txt";
	SecretKey key;

	public static void main(String[] args) {

		//exemplo run configuration: 45678 keystore.server server123
		if(args.length < 3) {
			System.out.println("Wrong number of arguments");
			System.out.println("Example: SeiTchizServer 45678 <keystore> <keystore-password>");
			System.exit(-1);
		}

		System.setProperty("javax.net.ssl.keyStore", args[1]);
		System.setProperty("javax.net.ssl.keyStorePassword", args[2]);

		System.out.println("Server iniciated");
		SeiTchizServer server = new SeiTchizServer();
		server.startServer(Integer.parseInt(args[0]));
	}

	public void startServer (int tcpPort){

		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
		SSLServerSocket serverSocket = null;

		try {

			/* - primeira fase
			serverSocket = new ServerSocket(tcpPort);
			serverSocket.setReuseAddress(true);
			 */

			serverSocket = (SSLServerSocket) ssf.createServerSocket(tcpPort);

		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		try {
			startup();
		} catch (IOException e) {
			System.err.println("Error creating server files");
			System.exit(-1);		
		}

		//listen to clients
		while(true) {
			try {
				new ServerThread(serverSocket.accept()).start();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void startup() throws IOException{

		File serverKey = new File("serverKey.key");
		generateServerKey(serverKey);

		File userLogins = new File(USER_LOGINS_TXT_LOCATION);
		if (userLogins.createNewFile())
			createUserLoginFile(userLogins);

		File file = new File("Clients");
		file.mkdirs();

		File file2 = new File("Groups");
		file2.mkdirs();

		File file3 = new File("PubKeys");
		file3.mkdirs();

		File file4 = new File("ClientPhotoFiles");
		file4.mkdirs();

	}

	private void createUserLoginFile(File userLogins) throws IOException {

		try {
			Cipher c;
			c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);

			FileOutputStream fos = new FileOutputStream(userLogins);

			File aux = new File("aux1.txt");

			FileOutputStream fos1 = new FileOutputStream(aux);
			ObjectOutputStream ois = new ObjectOutputStream(fos1);
			ois.writeBytes("clientID,chave publica \n");

			ois.close();
			fos1.close();

			FileInputStream fis = new FileInputStream(aux);

			CipherOutputStream cos = new CipherOutputStream(fos, c);
			byte[] b = new byte[16];  

			int i = fis.read(b);
			while (i != -1) {
				cos.write(b, 0, i);
				i = fis.read(b);
			}

			cos.close();
			fis.close();
			fos.close();

			aux.delete();

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	private void generateServerKey(File serverKey) throws IOException {

		try{

			if (serverKey.createNewFile()) {
				KeyGenerator kg;
				kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				key = kg.generateKey();
				byte[] keyEncoded = key.getEncoded();
				FileOutputStream fos = new FileOutputStream(serverKey);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(keyEncoded);
				oos.close();
				fos.close();
			}
			else {

				FileInputStream fis = new FileInputStream(serverKey);
				ObjectInputStream ois = new ObjectInputStream(fis);
				byte[] keyEncoded;

				keyEncoded = (byte[]) ois.readObject();
				key = new SecretKeySpec(keyEncoded, "AES");
				ois.close();

			}
		}catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	//Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private static final String PUB_KEYS_LOCATION = "PubKeys/";
		private static final String CERTIFICATE_EXTENSION = ".cert";
		private static final String NOT_FOLLOWING_USER = "You are not following this user";
		private static final String REMOVE_YOURSELF_FROM_GROUP = "You cannot remove yourself from a group you created";
		private static final String GROUP_ALREADY_EXISTS = "This group already exists";
		private static final String UNFOLLOW_YOURSELF_ERROR = "You can not unfollow yourself";
		private static final String FOLLOW_YOURSELF_ERROR = "You can not follow yourself";
		private static final String ALREADY_FOLLOWING_USER = "You are already following this user";
		private static final String USER_ALREADY_IN_GROUP = "This user is already in the group";
		private static final String USER_ID_DOES_NOT_EXIST = "This userID does not exist";
		private static final String PHOTO_ID_DOES_NOT_EXIST = "This photoID does not exist";
		private static final String USER_NOT_IN_THE_GROUP = "This user is not in the group";
		private static final String NOT_FOUND_GROUP = "This group does not exist";
		private static final String NOT_OWNER = "You are not the owner of this group";
		private static final String NOT_MEMBER = "You are not a member of this group";

		private Socket socket = null;
		private Client currentClient;
		private ObjectOutputStream out = null;
		private ObjectInputStream in = null;


		ServerThread(Socket clientSocket) {
			socket = clientSocket;
		}

		public void run(){

			try {

				out = new ObjectOutputStream(socket.getOutputStream());
				in = new ObjectInputStream(socket.getInputStream());

				//authentication
				String username = null;
				username = (String) in.readObject();

				boolean clientAccess = login(username);

				if(!clientAccess) {
					return;
				}

				currentClient = loadClient(username);

				if(currentClient == null) { 

					currentClient = new Client(username);
					saveClientToDisk(currentClient);
				}

				while(true) {
					processRequest();
				}

			}catch (IOException e) {
				//maybe ignore message
				//e.printStackTrace();
				System.out.println("Error communicating or client closed, closing this connection");
			} catch (ClassNotFoundException | NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}

		private boolean login(String username) throws IOException {

			File txt = usersDecifrado();
			BufferedReader br = new BufferedReader(new FileReader(txt));
			String line;

			boolean registado = false;
			String nomeCertificado = null;

			//ver se esta registado
			while((line = br.readLine()) != null) {
				String[] login = line.split(":");
				if(login[0].equals(username)) {
					nomeCertificado = login[1];
					registado = true;
				}
			}

			br.close();

			//criar um nonce long
			long nonce = new Random().nextLong();

			if (registado) {
				out.writeObject(new Message(Commands.AUTHENTICATION, nonce));
				txt.delete();
				return verificarClient(nonce, nomeCertificado);
			}
			else {
				out.writeObject(new Message(Commands.REGISTER, nonce));
				return register(nonce, username, txt);
			}
		}

		private File usersDecifrado() {

			File usersTxt = new File("usersAux.txt");

			Cipher c;

			try {
				c = Cipher.getInstance("AES");
				c.init(Cipher.DECRYPT_MODE, key);

				//leio do cifrado
				FileInputStream fis = new FileInputStream(USER_LOGINS_TXT_LOCATION);
				//escrevo no aux
				FileOutputStream fos = new FileOutputStream(usersTxt);

				CipherOutputStream cos = new CipherOutputStream(fos, c);

				byte[] b = new byte[16];
				int i = fis.read(b);

				while ( i != -1) {
					cos.write(b, 0, i);
					i = fis.read(b);
				}

				cos.close();
				fos.close();
				fis.close();

				return usersTxt; 

			} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			return null;
		}

		private boolean register(long nonce, String client, File txt) {

			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(nonce);
			byte[] n = buffer.array();

			try {

				Message m = (Message) in.readObject();

				if (nonce != m.getNonce()) {
					out.writeObject(new Message(Commands.INVALID_LOGIN, "Wrong nonce"));
					return false;
				}

				byte[] signature = m.getSignature(); 

				Certificate c = m.getCertificate();
				PublicKey pk = c.getPublicKey( );

				Signature s = Signature.getInstance("MD5withRSA");

				s.initVerify(pk);
				s.update(n);

				if (s.verify(signature)) {
					out.writeObject(new Message(Commands.LOGIN_SUCCESS, "By register"));

					BufferedWriter bw = new BufferedWriter(new FileWriter(txt,true));

					bw.write(client + ":" + client + CERTIFICATE_EXTENSION);
					bw.newLine();
					bw.close();

					saveCertificadoToDisk(c, client);

					usersCifrado(txt);
					return true;
				}
				else {
					out.writeObject(new Message(Commands.INVALID_LOGIN, "Cant verify signiture"));
					return false;
				}


			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}

			return false;
		}

		private void usersCifrado(File txt) {

			Cipher c;

			try {
				c = Cipher.getInstance("AES");
				c.init(Cipher.ENCRYPT_MODE, key);

				FileInputStream fis = new FileInputStream(txt);

				FileOutputStream fos =  new FileOutputStream(USER_LOGINS_TXT_LOCATION);

				CipherOutputStream cos = new CipherOutputStream(fos, c);
				byte[] b = new byte[16];  

				int i = fis.read(b);
				while (i != -1) {
					cos.write(b, 0, i);
					i = fis.read(b);
				}

				cos.close();
				fis.close();
				fos.close();

				txt.delete();


			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private boolean verificarClient(long nonce, String nomeCertificado) {

			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(nonce);
			byte[] n = buffer.array();

			FileInputStream fis2;
			try {

				Message m = (Message) in.readObject();
				
				if (nonce != m.getNonce()) {

					out.writeObject(new Message(Commands.INVALID_LOGIN, "Wrong nonce"));
					return false;
				}
				

				byte[] signature = m.getSignature(); 

				fis2 = new FileInputStream(PUB_KEYS_LOCATION + nomeCertificado);
				ObjectInputStream ois = new ObjectInputStream(fis2);
				byte[] b = (byte[]) ois.readObject();
				ois.close();
				
				CertificateFactory cf = CertificateFactory.getInstance("X509");
				Certificate c = cf.generateCertificate(new ByteArrayInputStream(b));

				PublicKey pk = c.getPublicKey( );

				Signature s = Signature.getInstance("MD5withRSA");
				s.initVerify(pk);
				s.update(n);
				if (s.verify(signature)) {
					out.writeObject(new Message(Commands.LOGIN_SUCCESS, "Authenticated"));
					return true;
				}
				else {
					out.writeObject(new Message(Commands.INVALID_LOGIN, "Cant verify signiture"));
					return false;
				}

			} catch (FileNotFoundException e) {
				System.err.println("Client Certificate not in PubKeys" + e.getMessage());
				try {
					out.writeObject(new Message(Commands.ERROR, "Client Certificate not in PubKeys"));
				} catch (IOException e1) {
					e1.printStackTrace();
				}				
			} 
			catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			} catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}

			return false;
			
		}

		private void processRequest() throws ClassNotFoundException, IOException, NoSuchAlgorithmException {

			Message request = (Message) in.readObject();
			currentClient = loadClient(currentClient.getUsername());

			switch(request.getType()) {

			case FOLLOW:
				followRequest(request);
				break;

			case UNFOLLOW:
				unfollowRequest(request);
				break;

			case VIEWFOLLOWERS:
				viewFollowersRequest();
				break;

			case POST:
				postRequest(request);
				break;

			case WALL:
				wallRequest(request);
				break;

			case LIKE:
				likeRequest(request);
				break;

			case NEWGROUP:
				newGroup(request);
				break;

			case ADDU:
				addUserGroup(request);
				break;

			case REMOVEU:
				removeUserGroup(request);
				break;

			case GINFO:
				groupInfo(request);
				break;

			case MSG:
			case CHAVE:
				message(request);
				break;

			case COLLECT:
				collect(request);
				break;

			case HISTORY:
				history(request);
				break;

			default:
				break;
			}

			saveClientToDisk(currentClient);
		}

		private void history(Message request) throws IOException {

			Group group = loadGroup(request.getMessage());

			if (group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			if (!group.isMember(currentClient.getUsername())) {
				Message m = new Message(Commands.ERROR, NOT_MEMBER);
				out.writeObject(m);
				return;
			}

			Message m = new Message(Commands.HISTORY, group.getFromHistory(currentClient.getUsername()));
			out.writeObject(m);
		}

		private void collect(Message request) throws IOException {

			Group group = loadGroup(request.getMessage());

			if (group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			if (!group.isMember(currentClient.getUsername())) {
				Message m = new Message(Commands.ERROR,  NOT_MEMBER);
				out.writeObject(m);
				return;
			}

			Message m = new Message(Commands.COLLECT, group.collect(currentClient.getUsername()));
			out.writeObject(m);

			saveGroupToDisk(group);	

		}

		private void message(Message request) throws ClassNotFoundException, IOException {


			Group group = loadGroup(request.getGrupoAtual());

			if (group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			if (!group.isMember(currentClient.getUsername())) {
				Message m = new Message(Commands.ERROR,  NOT_MEMBER);
				out.writeObject(m);
				return;
			}

			if (request.getType() == Commands.CHAVE) {

				SecretKey wrapClientKey = group.getWrapKey(currentClient.getUsername());
				int lastID = group.getLastId();
				out.writeObject(new Message(Commands.CHAVE, wrapClientKey, lastID));
				request = (Message) in.readObject();

			}

			if (request.getKeyId() != group.getLastId()) {
				SecretKey wrapClientKey = group.getWrapKey(currentClient.getUsername());
				int lastID = group.getLastId();
				out.writeObject(new Message(Commands.WRONGKEY, wrapClientKey, lastID));
				request = (Message) in.readObject();

			}
			else {
				out.writeObject(new Message(Commands.OK));
			}

			group.sendMessage(request.getMessage(), request.getKeyId());

			Message m = new Message(Commands.OK);
			out.writeObject(m);

			saveGroupToDisk(group);	

		}

		private void groupInfo(Message request) throws IOException {

			//mandar grupos que pertence e eh dono
			if (request.getMessage().isEmpty()) {
				Message m = new Message(Commands.GINFO, currentClient.groupsIOwn(), currentClient.groups(), null);
				out.writeObject(m);
				return;
			}

			Group group = loadGroup(request.getMessage());

			if (group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			if (!group.isMember(currentClient.getUsername())) {
				Message m = new Message(Commands.ERROR,  NOT_MEMBER);
				out.writeObject(m);
				return;
			}

			if(!group.getOwner().equals(currentClient.getUsername())) {
				Message m = new Message(Commands.ERROR,  NOT_OWNER);
				out.writeObject(m);
				return;
			}

			Message m = new Message(Commands.GINFO, null, null, group.members());

			out.writeObject(m);	
		}

		private void removeUserGroup(Message request) throws ClassNotFoundException, IOException {

			// [0] - user; [1] - idgroup
			String[] args = request.getMessage().split(" ");

			Group group = loadGroup(args[1]);

			if(group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			Client oldUser = loadClient(args[0]);

			if(oldUser == null) {
				Message m = new Message(Commands.ERROR, USER_ID_DOES_NOT_EXIST);
				out.writeObject(m);
				return;
			}

			String gOwner = group.getOwner();

			if (!currentClient.getUsername().equals(gOwner)) {
				Message m = new Message(Commands.ERROR, NOT_OWNER);
				out.writeObject(m);
				return;
			}

			if(!group.isMember(args[0])) {
				Message m = new Message(Commands.ERROR, USER_NOT_IN_THE_GROUP);
				out.writeObject(m);
				return;
			}

			if(currentClient.getUsername().equals(args[0])) {
				String error = REMOVE_YOURSELF_FROM_GROUP;
				Message m = new Message(Commands.ERROR, error);
				out.writeObject(m);
				return;
			}

			List<Entry<String,String>> usersNomesECert = new ArrayList<>();

			for(String m : group.members()) {
				usersNomesECert.add(new AbstractMap.SimpleEntry<>(m, PUB_KEYS_LOCATION + m + CERTIFICATE_EXTENSION));
			}

			out.writeObject(new Message(Commands.OK, usersNomesECert));

			Message chaves = (Message) in.readObject();

			group.remove(args[0], chaves.getMensagesCifradasOuNovasChaves());

			oldUser.removeGroup(args[1]);

			out.writeObject(new Message(Commands.OK));

			saveGroupToDisk(group);
			saveClientToDisk(oldUser);
		}

		private void addUserGroup(Message request) throws ClassNotFoundException, IOException {

			// [0] - user; [1] - idgroup
			String[] args = request.getMessage().split(" ");

			Group group = loadGroup(args[1]);

			if(group == null) {
				Message m = new Message(Commands.ERROR, NOT_FOUND_GROUP);
				out.writeObject(m);
				return;
			}

			Client newUser = loadClient(args[0]);
			
			if(newUser == null) {
				Message m = new Message(Commands.ERROR, USER_ID_DOES_NOT_EXIST);
				out.writeObject(m);
				return;
			}

			String gOwner = group.getOwner();

			if (!currentClient.getUsername().equals(gOwner)) {
				Message m = new Message(Commands.ERROR, NOT_OWNER);
				out.writeObject(m);
				return;
			}

			if(group.isMember(newUser.getUsername())) {
				Message m = new Message(Commands.ERROR, USER_ALREADY_IN_GROUP);
				out.writeObject(m);
				return;
			}

			List<Entry<String,String>> usersNomesECert = new ArrayList<>();

			for(String m : group.members()) {
				usersNomesECert.add(new AbstractMap.SimpleEntry<>(m, PUB_KEYS_LOCATION + m + CERTIFICATE_EXTENSION));
			}

			out.writeObject(new Message(Commands.OK, usersNomesECert));

			Message chaves = (Message) in.readObject();

			group.add(args[0], chaves.getMensagesCifradasOuNovasChaves());
			newUser.newGroup(args[1]);

			saveGroupToDisk(group);
			saveClientToDisk(newUser);

			Message m = new Message(Commands.OK);
			out.writeObject(m);
		}

		private void newGroup(Message request) throws IOException {

			String id = request.getMessage();

			Group g = loadGroup(id);

			if(g != null) {
				Message m = new Message(Commands.ERROR, GROUP_ALREADY_EXISTS);
				out.writeObject(m);
				return;
			}

			SecretKey wrappedKey = request.getWrappedKey();

			g = new Group(id, currentClient.getUsername(), wrappedKey);

			currentClient.newGroupAsOwner(id);
			saveGroupToDisk(g);

			Message m = new Message(Commands.OK);
			out.writeObject(m);

		}

		private void wallRequest(Message request) throws IOException, NoSuchAlgorithmException {

			int nWall = request.getWallN();
			List<SeiTchizPhoto> wall = new ArrayList<>(nWall);

			List<String> followingUsers = currentClient.getFollowingUsers();

			for(String user : followingUsers) {
				Client currentFollower = loadClient(user);
				
				if(currentFollower == null)
					continue;
				
				List<SeiTchizPhoto> currentFollowerPhotos = currentFollower.getPhotos();
				for(int j = 0; j < currentFollowerPhotos.size(); j++){
					if(wall.size() < nWall)
						wall.add(currentFollowerPhotos.get(j));
					else {
						ArrayList<Long> wallDates = wall
								.stream()
								.map(SeiTchizPhoto::getCreationDate)
								.collect(Collectors.toCollection(ArrayList::new));

						long min = Collections.min(wallDates);
						if (currentFollowerPhotos.get(j).getCreationDate() > min) {
							wall.set(wallDates.indexOf(min), currentFollowerPhotos.get(j));
						}
					}
				}
			}

			Collections.sort(wall);

			List<PhotoInfo> sendingPhotos = new ArrayList<>();
			for(SeiTchizPhoto p : wall) {
				PhotoInfo pi = new PhotoInfo(p.getPhoto(), p.getLikes(), 
						p.getOwner(), p.getId(), p.getExtension());
				sendingPhotos.add(pi);
			}
			Message response = new Message(Commands.WALL, request.getWallN(), sendingPhotos);
			out.writeObject(response);
		}		

		private void likeRequest(Message request) throws IOException {

			Message response;
			String photoID = request.getMessage();
			String photoOwner = photoID.split("_")[0];
			Client owner = loadClient(photoOwner);

			if(owner == null) {
				response = new Message(Commands.ERROR, PHOTO_ID_DOES_NOT_EXIST);
				out.writeObject(response);
				return;
			}

			boolean added = false;
			if(photoOwner.equals(currentClient.getUsername()))
				added = currentClient.addLikeToPhoto(photoID, currentClient.getUsername());
			else
				added = owner.addLikeToPhoto(photoID, currentClient.getUsername());
			if(added){
				saveClientToDisk(owner);
				response = new Message(Commands.OK);
				out.writeObject(response);
			}
			else {
				response = new Message(Commands.ERROR, PHOTO_ID_DOES_NOT_EXIST);
				out.writeObject(response);
			}
		}

		private void postRequest(Message request) throws IOException, NoSuchAlgorithmException {

			currentClient.addPhoto(new SeiTchizPhoto(request.getPostPhoto(), 
					currentClient.getUsername(), request.getMessage()));

			Message response = new Message(Commands.OK);
			out.writeObject(response);
		}

		private void viewFollowersRequest() throws IOException {

			Message response;
			List<String> followers = currentClient.listFollowers();
			if(followers.isEmpty()) {
				response = new Message(Commands.ERROR, 
						"You do not have followers");
				out.writeObject(response);
			}
			else {
				response = new Message(Commands.VIEWFOLLOWERS, followers);
				out.writeObject(response);
			}
		}

		private void unfollowRequest(Message request) throws IOException {

			Message response;
			Client otherClient = loadClient(request.getMessage());

			if(currentClient.getUsername().equals(request.getMessage())) {
				response = new Message(Commands.ERROR, UNFOLLOW_YOURSELF_ERROR);
				out.writeObject(response);
			}
			else if(otherClient != null) {

				if(currentClient.unfollow(request.getMessage())) {

					otherClient.removeFollower(currentClient.getUsername());
					saveClientToDisk(otherClient);

					response = new Message(Commands.OK);
					out.writeObject(response);
				}
				else {
					response = new Message(Commands.ERROR, NOT_FOLLOWING_USER);
					out.writeObject(response);
				}
			}
			else {
				response = new Message(Commands.ERROR, USER_ID_DOES_NOT_EXIST);
				out.writeObject(response);
			}
		}

		private void followRequest(Message request) throws IOException {

			Message response;

			Client otherClient = loadClient(request.getMessage());

			if(currentClient.getUsername().equals(request.getMessage())) {
				response = new Message(Commands.ERROR, FOLLOW_YOURSELF_ERROR);
				out.writeObject(response);
			}
			else if(otherClient != null) {


				if(currentClient.follow(request.getMessage())) {

					otherClient.newFollower(currentClient.getUsername());
					saveClientToDisk(otherClient);

					response = new Message(Commands.OK);
					out.writeObject(response);
				}
				else {
					response = new Message(Commands.ERROR, ALREADY_FOLLOWING_USER);
					out.writeObject(response);
				}
			}
			else {
				response = new Message(Commands.ERROR, USER_ID_DOES_NOT_EXIST);
				out.writeObject(response);
			}
		}

		private void saveClientToDisk(Client c) throws IOException {

			FileOutputStream fos = new FileOutputStream("Clients/"+ c.getUsername() + ".scu");
			cipherObject(c, fos);
			fos.close();
		}

		private void saveGroupToDisk(Group g) throws IOException {

			FileOutputStream fos = new FileOutputStream("Groups/"+ g.getId() + ".scg");
			cipherObject(g, fos);
			fos.close();

		}

		private void saveCertificadoToDisk(Certificate c, String cliente) throws IOException {

			FileOutputStream fos = new FileOutputStream(PUB_KEYS_LOCATION + cliente + CERTIFICATE_EXTENSION);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			try {
				oos.writeObject(c.getEncoded());
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
			}
			oos.close();
		}

		private Client loadClient(String userID){

			File f = new File("Clients/"+ userID + ".scu");

			if(!f.exists())
				return null;

			return (Client) decipherObject(f);
		}

		private Group loadGroup(String groupID){

			File f = new File("Groups/" + groupID + ".scg");

			if (!f.exists()) {
				return null;
			}

			return (Group) decipherObject(f);
		}

		private void cipherObject(Object c, FileOutputStream fos){

			try {
				
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.ENCRYPT_MODE, key);

				CipherOutputStream cipherOutputStream = new CipherOutputStream(fos, cipher);
				ObjectOutputStream oos = new ObjectOutputStream(cipherOutputStream);

				oos.writeObject(c);
				oos.close();
				
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}

		private Object decipherObject(File f) {

			try {
				
				Cipher cDec;
				cDec = Cipher.getInstance("AES");
				cDec.init(Cipher.DECRYPT_MODE, key);

				FileInputStream fis = new FileInputStream(f);
				CipherInputStream cis = new CipherInputStream(fis, cDec);
				ObjectInputStream ois = new ObjectInputStream(cis);
				Object o = ois.readObject();
				ois.close();
				
				return o;

			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
			return null;

		}
	}
}
