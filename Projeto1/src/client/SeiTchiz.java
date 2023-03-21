/**
 * Seguranca e Confiabilidade 2020/21
 * Trabalho 1
 * 
 * @author Catarina Lima 52787
 * @author Andre Silva 52809
 * @author Joao Oliveira 52839
 */

package client;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import lib.Commands;
import lib.Message;
import lib.PhotoInfo;

public class SeiTchiz {

	private static final String WRONG_NUMBER_OF_ARGUMENTS = "Wrong number of arguments";
	static ObjectOutputStream out;
	static ObjectInputStream in;
	static String username;
	static KeyStore kstore;
	static Map<String, Entry<SecretKey, Integer>> chavesRecentesGrupos = new HashMap<>();
	static PrivateKey prk;

	public static void main(String[] args) {

		if(args.length < 5) {
			System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
			//											0				1			2				3				4
			System.out.println("Example: SeiTchiz <serverAddress> <truststore> <keystore> <keystore-password> <clientID>");
			System.exit(-1);
		}

		System.setProperty("javax.net.ssl.trustStore", args[1]);

		SocketFactory sf = SSLSocketFactory.getDefault();
		SSLSocket socket = null;

		String[] hostPort = args[0].split(":");
		String host = hostPort[0];

		//default
		int tcpPort = 45678;

		if(hostPort.length == 2)
			tcpPort = Integer.parseInt(hostPort[1]);

		try {

			FileInputStream kfile = new FileInputStream(args[2]); 
			kstore = KeyStore.getInstance("JCEKS");
			kstore.load(kfile, args[3].toCharArray());
			prk = (PrivateKey) kstore.getKey(kstore.aliases().nextElement(), args[3].toCharArray());


			socket = (SSLSocket) sf.createSocket(host, tcpPort);

			out = new ObjectOutputStream(socket.getOutputStream());
			in = new ObjectInputStream(socket.getInputStream());

			System.out.println("Connected to server");

			//ClientID
			username = args[4];

			if(username.matches(".*[\\\\/:*?\"<>|].*")){
				System.err.println("\nInvalid username. Characters \"\\ / : * ? \" < > | \" not allowed");
				System.exit(-1);
			}

			Scanner sc = new Scanner(System.in);

			out.writeObject(username);

			Message auth = (Message) in.readObject();

			if (auth.getType() == Commands.AUTHENTICATION) {

				long nonce = auth.getNonce();

				ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
				buffer.putLong(nonce);
				byte[] n = buffer.array();

				Signature s = Signature.getInstance("MD5withRSA");
				s.initSign(prk);
				s.update(n);


				out.writeObject(new Message(Commands.AUTHENTICATION, nonce, s.sign(), null));

				auth = (Message) in.readObject();
			}

			else if(auth.getType() == Commands.REGISTER) {

				long nonce = auth.getNonce();

				ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
				buffer.putLong(nonce);
				byte[] n = buffer.array();

				Certificate cert = kstore.getCertificate(kstore.aliases().nextElement()); 

				Signature s = Signature.getInstance("MD5withRSA");
				s.initSign(prk);
				s.update(n);
				out.writeObject(new Message(Commands.REGISTER, nonce, s.sign(), cert));

				auth = (Message) in.readObject();
			}

			if(auth.getType() == Commands.LOGIN_SUCCESS) {
				System.out.println(auth.getMessage());
				System.out.println(menuToString());
			}
			else if(auth.getType() == Commands.ERROR) {
				System.err.println(auth.getMessage());
				System.exit(-1);
			}
			else if(auth.getType() == Commands.INVALID_LOGIN) {
				System.err.println(auth.getMessage());
				System.exit(-1);
			}

			String command = null;

			while(!(command = sc.nextLine()).equals("quit")) {
				readCommand(command);
			}

			sc.close();

		} catch (UnknownHostException e) {
			System.err.println("Unknown Host: "+ e.getMessage());
		} catch (ConnectException e) {
			System.err.println("Error connecting to server, maybe wrong port or server offline");
		} catch (IOException e) {
			System.err.println("Error communicating with server");
			//e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException e) {
			e.printStackTrace();
		} catch (SignatureException | CertificateException | UnrecoverableKeyException e) {
			e.printStackTrace();
		}
	}

	private static void readCommand(String command) throws IOException, ClassNotFoundException {

		Message members;

		Cipher c;

		List<Entry<String, SecretKey>> novasChaves;

		String[] commandArray = command.split(" ");
		String args = "";
		KeyGenerator kg;
		SecretKey wrappedKey = null;

		for (int i = 1; i < commandArray.length; i++) {
			if (i == 1) 
				args = commandArray[i];

			else
				args = args + " " + commandArray[i];
		}

		try {

			switch (commandArray[0]) {

			case "follow":
			case "f":

				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: follow <userID>");
					return;
				}
				out.writeObject(new Message(Commands.FOLLOW, commandArray[1]));
				break;

			case "unfollow":
			case "u":

				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: unfollow <userID>");
					return;
				}
				out.writeObject(new Message(Commands.UNFOLLOW, commandArray[1]));
				break;

			case "viewfollowers":
			case "v":

				out.writeObject(new Message(Commands.VIEWFOLLOWERS));
				break;

			case "post":
			case "p":

				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: post <photo>");
					System.out.println("<photo> is the path to the file in this directory");
					System.out.println("Example: Photos/X.png");
					return;
				}
				if(post(commandArray[1])) {
					receiveResponse();
					return;
				}
				else
					return;

			case "wall":
			case "w":

				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: wall <nPhotos>");
					System.out.println("Where nPhotos is the number of most recent photos");
					return;
				}


				int nWall = Integer.parseInt(commandArray[1]);

				if(nWall <= 0) {
					System.out.println("<nPhotos> must be a positive integer (> 0)");
					return;
				}
				out.writeObject(new Message(Commands.WALL, nWall));



				break;

			case "like":
			case "l":
				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: like <photoID>");
					return;
				}

				out.writeObject(new Message(Commands.LIKE, commandArray[1]));
				break;

			case "newgroup":
			case "n":
				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: newgroup <groupID>");
					return;
				}

				kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				SecretKey groupKey = kg.generateKey();

				c = Cipher.getInstance("RSA");

				Certificate cert = kstore.getCertificate(kstore.aliases().nextElement()); 
				PublicKey pubKey = cert.getPublicKey();

				c.init(Cipher.WRAP_MODE, pubKey);

				wrappedKey = new SecretKeySpec(c.wrap(groupKey), "AES");


				out.writeObject(new Message(Commands.NEWGROUP, args, wrappedKey));

				break;

			case "addu":
			case "a":
				if(commandArray.length != 3) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: addu <userID> <groupID>");
					return;
				}

				out.writeObject(new Message(Commands.ADDU, args));
				members = (Message) in.readObject();

				if (members.getType() == Commands.ERROR) {
					tratarErro(members);
					return;
				}

				novasChaves = novasChavesGrupo(members, commandArray, true);

				out.writeObject(new Message(Commands.ADDU, novasChaves));

				break;

			case "removeu":
			case "r":

				if(commandArray.length != 3) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: removeu <userID> <groupID>");
					return;
				}

				out.writeObject(new Message(Commands.REMOVEU, args));
				members = (Message) in.readObject();

				if (members.getType() == Commands.ERROR) {
					tratarErro(members);
					return;
				}

				novasChaves = novasChavesGrupo(members, commandArray, false);

				out.writeObject(new Message(Commands.REMOVEU, novasChaves));

				break;

			case "ginfo":
			case "g":
				if(commandArray.length > 3) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: ginfo [groupID]"); 
					return;
				}

				out.writeObject(new Message(Commands.GINFO, args));
				break;

			case "msg":
			case "m":

				if(commandArray.length < 3) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: msg <groupID> <msg>");
					return;
				}

				if(!chavesRecentesGrupos.containsKey(commandArray[1])) {

					//esta Message tem k ter o id da chave!!!!!!!!!!!
					//escolhi esta construtor pra poder poupar linhas server
					out.writeObject(new Message(Commands.CHAVE, commandArray[1]));
					Message response = (Message) in.readObject();

					if (response.getType() == Commands.ERROR) {
						tratarErro(response);
						return;
					}

					chavesRecentesGrupos.put(commandArray[1],
							new AbstractMap.SimpleEntry<>(response.getWrappedKey(), response.getKeyId()));
				}

				Cipher dc = Cipher.getInstance("RSA");
				dc.init(Cipher.UNWRAP_MODE, prk);
				Key unwrappedKey = dc.unwrap(chavesRecentesGrupos.get(commandArray[1]).getKey().getEncoded(), "AES", Cipher.SECRET_KEY);

				c = Cipher.getInstance("AES");
				c.init(Cipher.ENCRYPT_MODE, unwrappedKey);

				String msg = commandArray[2];

				for (int i = 3; i < commandArray.length; i++) {
					msg += " " + commandArray[i];

				}

				String sC = new String(Base64.getEncoder().encode(c.doFinal(msg.getBytes())));

				out.writeObject(new Message(Commands.MSG, sC, commandArray[1], chavesRecentesGrupos.get(commandArray[1]).getValue()));


				Message response = (Message) in.readObject();

				if (response.getType() == Commands.WRONGKEY) {
					chavesRecentesGrupos.replace(commandArray[1],
							new AbstractMap.SimpleEntry<>(response.getWrappedKey(), response.getKeyId()));

					unwrappedKey = dc.unwrap(chavesRecentesGrupos.get(commandArray[1]).getKey().getEncoded(), "AES", Cipher.SECRET_KEY);

					c.init(Cipher.ENCRYPT_MODE, unwrappedKey);


					sC = new String(Base64.getEncoder().encode(c.doFinal(msg.getBytes())));

					out.writeObject(new Message(Commands.MSG, sC, commandArray[1], chavesRecentesGrupos.get(commandArray[1]).getValue()));
				}

				break;

			case "collect":
			case "c":
				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: msg <groupID>");
					return;
				}

				out.writeObject(new Message(Commands.COLLECT, args));
				break;

			case "history":
			case "h":
				if(commandArray.length != 2) {
					System.out.println(WRONG_NUMBER_OF_ARGUMENTS);
					System.out.println("Example: history <groupID>");
					return;
				}

				out.writeObject(new Message(Commands.HISTORY, args));
				break;

			default:
				System.out.println("Command not recognized");
				return;
			}

		}catch (NumberFormatException e) {
			System.out.println("<nPhotos> must be a positive integer (> 0)");
		}catch (InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException | NoSuchPaddingException | KeyStoreException e) {
			e.printStackTrace();
		}
		receiveResponse();

	}

	private static List<Entry<String, SecretKey>> novasChavesGrupo(Message members, String[] commandArray, boolean add) {

		Certificate membro;
		FileInputStream fis;
		ObjectInputStream ois;
		CertificateFactory cf;
		byte[] b;
		PublicKey pkM;
		SecretKey wrapMembro;
		List<Entry<String, SecretKey>> novasChaves;
		KeyGenerator kg;
		novasChaves = new ArrayList<>();

		try {

			kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey groupKey = kg.generateKey();

			Cipher c2 = Cipher.getInstance("RSA");

			List<String> nomesCert = members.getListaNomesCert().stream()
					.map(Entry::getValue).collect(Collectors.toList());

			List<String> usernames = members.getListaNomesCert().stream()
					.map(Entry::getKey).collect(Collectors.toList());

			if(add) {
				String nomeCertNovoMembro = "PubKeys/"+commandArray[1]+".cert";

				nomesCert.add(nomeCertNovoMembro);
				usernames.add(commandArray[1]);
			}
			else {
				int userARemover = usernames.indexOf(commandArray[1]);
				usernames.remove(userARemover);
				nomesCert.remove(userARemover);
			}

			for(int i = 0; i < nomesCert.size(); i++) {

				String nomeCertMembro = nomesCert.get(i);
				fis = new FileInputStream(nomeCertMembro);
				ois = new ObjectInputStream(fis);
				b = (byte[]) ois.readObject();

				cf = CertificateFactory.getInstance("X509");
				membro = cf.generateCertificate(new ByteArrayInputStream(b));
				pkM = membro.getPublicKey();

				c2.init(Cipher.WRAP_MODE, pkM);
				wrapMembro = new SecretKeySpec(c2.wrap(groupKey), "RSA");

				novasChaves.add(new AbstractMap.SimpleEntry<>(usernames.get(i), wrapMembro));

				fis.close();
				ois.close();
			}
			return novasChaves;

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (CertificateException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}

		return novasChaves;
	}

	private static void tratarErro(Message response) {

		System.err.println(response.getMessage());

	}

	private static void receiveResponse() throws ClassNotFoundException, IOException {

		List<Entry<String, SecretKey>> mensagensCifradas;
		Cipher dc;
		Cipher dcM;
		Key unwrappedKey;

		Message response = (Message) in.readObject();

		try {

			switch(response.getType()) {

			case OK:

				System.out.println("Operation executed successfully");
				break;

			case ERROR:

				System.err.println(response.getMessage());
				break;

			case VIEWFOLLOWERS:

				List<String> followers = response.getFollowers();

				System.out.println("Followers:");
				for (String userID: followers) {
					System.out.println(userID);
				}
				break;

			case GINFO:
				List<String> group = response.getGroupInfo();
				List<String> own = response.getOwnGroups();
				List<String> others = response.getGroups();
				if (group == null) {

					// sem grupos
					if (own == null && others == null) {
						System.out.println("You do not belong to any group nor own any");
						return;
					}

					if(own.isEmpty()) {
						System.out.println("You do not own any groups \n");
					}
					else {
						System.out.println("You are the owner of these groups:");
						for (String o : own) {
							System.out.println(o);
						}
					}

					if(others.isEmpty()) {
						System.out.println("You are not in any other group \n");
					}
					else {
						System.out.println("You are in these groups as well:");
						for (String o : others) {
							System.out.println(o);
						}
					}
				}

				else {
					for (int i = 0; i < group.size(); i++) {
						if (i == 0) {
							System.out.println("Owner of the group: " + group.get(i));
							System.out.println("Members of the group:");

						}
						else
							System.out.println(group.get(i));
					}
				}

				break;

			case COLLECT:

				mensagensCifradas = response.getMensagesCifradasOuNovasChaves();

				if (mensagensCifradas.isEmpty()) {
					System.out.println("There are no new messages");
				} else {
					System.out.println("New messages:");

					for (Entry<String, SecretKey> msg : mensagensCifradas) {

						dc = Cipher.getInstance("RSA");
						dcM= Cipher.getInstance("AES");

						dc.init(Cipher.UNWRAP_MODE, prk);

						unwrappedKey = dc.unwrap(msg.getValue().getEncoded(), "AES", Cipher.SECRET_KEY);

						dcM.init(Cipher.DECRYPT_MODE, unwrappedKey);

						String m = new String (dcM.doFinal(Base64.getDecoder().decode(msg.getKey().getBytes())));

						System.out.println(m);
					}
				}

				break;

			case HISTORY:

				mensagensCifradas = response.getMensagesCifradasOuNovasChaves();

				if (mensagensCifradas == null) {
					System.out.println("There are no past messages");
				} else {
					System.out.println("Past messages:");

					for (Entry<String, SecretKey> msg : mensagensCifradas) {

						dc = Cipher.getInstance("RSA");
						dcM= Cipher.getInstance("AES");

						dc.init(Cipher.UNWRAP_MODE, prk);
						unwrappedKey = dc.unwrap(msg.getValue().getEncoded(), "AES", Cipher.SECRET_KEY);
						dcM.init(Cipher.DECRYPT_MODE, unwrappedKey);

						String m = new String (dcM.doFinal(Base64.getDecoder().decode(msg.getKey().getBytes())));

						System.out.println(m);

					}
				}
				break;

			case WALL:

				List<PhotoInfo> photos = response.getWallPhotos();
				File file = new File("Wall" + username);
				file.mkdirs();

				if(photos.isEmpty()) {
					System.err.println("There are no photos to be shown");
				}
				for(PhotoInfo pi : photos) {

					if(pi.getPhoto() == null) {
						System.out.println("Error receiving photo with photoID: " + pi.getId() +
								", Integrity of this photo was compromised \n");
					}
					else {
						System.out.println("New photo saved in Wall" + username + " folder with photoID: "+pi.getId());
						System.out.println("From: "+ pi.getOwner());
						System.out.println("It has: " + pi.getLikes() + " likes");
						pi.saveImageFileToDisk("Wall" +username + "/");
					}
				}
				break;
			}

		} catch (InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	private static boolean post(String fileName) throws IOException {

		try {
			File imageFile = new File(fileName);
			String[] fileNameSplit = fileName.split("\\.");
			String extension = fileNameSplit[fileNameSplit.length - 1];

			byte[] imagebytes = Files.readAllBytes(imageFile.toPath());
			out.writeObject(new Message(Commands.POST, imagebytes, extension));
			return true;

		} catch (NoSuchFileException e) {
			System.err.println("File not found: "+fileName);
			return false;
		}
	}

	private static String menuToString() {

		return "Available operations: \n"+
				"- follow <userID> \n" + 
				"- unfollow <userID>\n" + 
				"- viewfollowers \n" + 
				"- post <photo> \n" + 
				"- wall <nPhotos> \n" + 
				"- like <photoID> \n" + 
				"- newgroup <groupID> \n" + 
				"- addu <userID> <groupID> \n" + 
				"- removeu <userID> <groupID> \n" + 
				"- ginfo [groupID] \n" + 
				"- msg <groupID> <msg> \n" + 
				"- collect <groupID> \n" + 
				"- history <groupID> \n"+
				"- quit\n";

	}

}


