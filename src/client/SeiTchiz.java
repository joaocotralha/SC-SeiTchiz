package client;

import java.io.IOException;
import java.nio.file.Files;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Scanner;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.Base64;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Key;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;


public class SeiTchiz {

	private static SeiTchiz user;
	private static SSLSocket ss = null;
	private static String clientID;
	private static String truststore;
	private static String keystore;
	private static String ksPassword;
	private static ObjectOutputStream outStream;
	private static ObjectInputStream inStream;
	private static String fs = System.getProperty("file.separator");
	private static String ls = System.lineSeparator();

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		if(args.length != 5) {
			System.out.println("Tem de usar os argumentos SeiTchiz <serverAddress> <truststore> <keystore> <keystore-password> <clientID>");
			return;
		}
		user = new SeiTchiz();

		System.out.println("- Cliente SeiTchiz -");

		String serverAddress = args[0];
		truststore = args[1];
		keystore = args[2];
		ksPassword = args[3];
		clientID = args[4];

		System.setProperty("javax.net.ssl.trustStore", truststore);
		System.setProperty("javax.net.ssl.keyStore", keystore);
		System.setProperty("javax.net.ssl.keyStorePassword", ksPassword);
		//System.setProperty("javax.net.ssl.trustStorePassword", ksPassword);

		String[] param = serverAddress.split(":");
		serverAddress = param[0];
		int port = Integer.parseInt(param[1]);

		SocketFactory ssf = SSLSocketFactory.getDefault();
		ss = (SSLSocket) ssf.createSocket(serverAddress, port);
		outStream = new ObjectOutputStream(ss.getOutputStream());
		inStream = new ObjectInputStream(ss.getInputStream());

		if(!user.autenticar(clientID)){
			outStream.writeObject("exit");
			user.sair();
			System.exit(0);
		}

		Scanner scan = new Scanner(System.in);

		System.out.println("Introduza um dos seguintes comandos, escrevendo o seu nome ou apenas a sua letra inicial e os respetivos parametros:");
		System.out.println("follow <userID>");
		System.out.println("unfollow <userID>");
		System.out.println("viewfollowers");
		System.out.println("post <photo>");
		System.out.println("wall <nPhotos>");
		System.out.println("like <photoID>");
		System.out.println("newgroup <groupID>");
		System.out.println("addu <userID> <groupID>");
		System.out.println("removeu <userID> <groupID>");
		System.out.println("ginfo [groupID]");
		System.out.println("msg <groupID> <msg>");
		System.out.println("collect <groupID>");
		System.out.println("history <groupID>");
		System.out.println("exit");

		while(true) {
			System.out.println(">>>");
			String comando = scan.nextLine();
			String[] cmd = comando.split(" ");

			if(cmd[0].equals("exit") || cmd[0].equals("e")) {
				outStream.writeObject(cmd[0]);
				scan.close();
				user.sair();
				System.exit(0);
			}

			user.sendReceive(cmd);
		}
	}

	private void sendReceive (String[] cmd) {
		try {
		  if((cmd[0].equals("follow") || cmd[0].equals("f")) && cmd.length>1) {
				defaultComm(cmd, 2);
			} else if((cmd[0].equals("unfollow") || cmd[0].equals("u")) && cmd.length>1) {
				defaultComm(cmd, 2);
			} else if(cmd[0].equals("viewfollowers") || cmd[0].equals("v")) {
				outStream.writeObject(cmd[0]);
				String recv = null;
				while(!(recv = (String) inStream.readObject()).equals("")){
					System.out.println(recv);
				}
			} else if((cmd[0].equals("post") || cmd[0].equals("p")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				String[] split = cmd[1].replace("\\", "/").split("/");

				outStream.writeObject(split[split.length-1]);
				send(cmd[1]);
			} else if((cmd[0].equals("wall") || cmd[0].equals("w")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);
				Object obj = inStream.readObject();
				if(obj instanceof Integer){
					System.out.println(inStream.readObject());
					receive((int) obj);
					System.out.println(inStream.readObject());
				} else {
					System.out.println((String) obj);
				}
			} else if((cmd[0].equals("like") || cmd[0].equals("l")) && cmd.length>1) {
				defaultComm(cmd, 2);
			} else if((cmd[0].equals("newgroup") || cmd[0].equals("n")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);

				KeyGenerator kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				SecretKey sk = kg.generateKey();

				Cipher c = Cipher.getInstance("RSA");

				KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
				FileInputStream fis = new FileInputStream(keystore);
				ks.load(fis, ksPassword.toCharArray());
				Key pk = ks.getKey(clientID, ksPassword.toCharArray());

				c.init(Cipher.WRAP_MODE, pk);

				byte[] wrappedKey = c.wrap(sk);

				outStream.writeObject(Base64.getEncoder().withoutPadding().encodeToString(wrappedKey));

				String recv = (String) inStream.readObject();
				if(recv.equals("Grupo ja existente")){
					return;
				}

				System.out.println(recv);

			} else if((cmd[0].equals("addu") || cmd[0].equals("a")) && cmd.length>2) {
				addOrRemoveU(cmd);
			} else if((cmd[0].equals("removeu") || cmd[0].equals("r")) && cmd.length>2) {
				addOrRemoveU(cmd);
			} else if((cmd[0].equals("ginfo") || cmd[0].equals("g")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);
				String recv = null;
				while(!(recv = (String) inStream.readObject()).equals("")){
					System.out.println(recv);
				}
			} else if((cmd[0].equals("ginfo") || cmd[0].equals("g"))) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject("");
				String recv = null;
				while(!(recv = (String) inStream.readObject()).equals("")){
					System.out.println(recv);
				}
			} else if((cmd[0].equals("msg") || cmd[0].equals("m")) && cmd.length>2) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);

				String recv = (String) inStream.readObject();
				if(!recv.contains(":")){
					System.out.println(recv);
					return;
				}

				LocalDateTime now = LocalDateTime.now();
				DateTimeFormatter dtf2 = DateTimeFormatter.ofPattern("HH:mm:ss dd/MM/yyyy");

				String msg = String.join(" ",cmd).substring(cmd[0].length()+cmd[1].length()+2);
				msg = ls+"Grupo - "+cmd[1]+ls+clientID+":"+ls+msg+" - enviada a "+dtf2.format(now)+ls;


				byte[] wrappedKey = Base64.getDecoder().decode(recv.substring(recv.indexOf(":")+1));

				KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
				FileInputStream fis = new FileInputStream(keystore);
				ks.load(fis, ksPassword.toCharArray());
				Key pk = ks.getKey(clientID, ksPassword.toCharArray());

				Cipher c = Cipher.getInstance("RSA");
				c.init(Cipher.UNWRAP_MODE, pk);
				Key unwrappedKey = c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

				c = Cipher.getInstance("AES/ECB/PKCS5Padding");
				c.init(Cipher.ENCRYPT_MODE, unwrappedKey);
				byte[] encrypted = c.doFinal(msg.getBytes());

				outStream.writeObject(Base64.getEncoder().withoutPadding().encodeToString(encrypted));
				System.out.println(inStream.readObject());
			} else if((cmd[0].equals("collect") || cmd[0].equals("c")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);

				KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
				FileInputStream fis = new FileInputStream(keystore);
				ks.load(fis, ksPassword.toCharArray());
				Key pk = ks.getKey(clientID, ksPassword.toCharArray());

				Cipher c = Cipher.getInstance("RSA");
				c.init(Cipher.UNWRAP_MODE, pk);

				String recv = (String) inStream.readObject();
				System.out.println(recv);
				if(!recv.contains("=")) {
					return;
				}

				while(!(recv = (String) inStream.readObject()).equals("")){
					String key = recv.split(":")[1];

					byte[] wrappedKey = Base64.getDecoder().decode(key);
					Key unwrappedKey = c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

					Cipher cMsg = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cMsg.init(Cipher.DECRYPT_MODE, unwrappedKey);

					String msg = (String) inStream.readObject();
					String msgDec = new String(cMsg.doFinal(Base64.getDecoder().decode(msg)));
					System.out.println(msgDec);
				}

				recv = (String) inStream.readObject();
				System.out.println(recv);
				if(!recv.contains("=")){
					System.out.println((String) inStream.readObject());
				}

			} else if((cmd[0].equals("history") || cmd[0].equals("h")) && cmd.length>1) {
				outStream.writeObject(cmd[0]);
				outStream.writeObject(cmd[1]);

				KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
				FileInputStream fis = new FileInputStream(keystore);
				ks.load(fis, ksPassword.toCharArray());
				Key pk = ks.getKey(clientID, ksPassword.toCharArray());

				Cipher c = Cipher.getInstance("RSA");
				c.init(Cipher.UNWRAP_MODE, pk);

				String recv = (String) inStream.readObject();
				System.out.println(recv);
				if(!recv.contains("=")) {
					return;
				}

				while(!(recv = (String) inStream.readObject()).equals("")){
					String key = recv.split(":")[1];

					byte[] wrappedKey = Base64.getDecoder().decode(key);
					Key unwrappedKey = c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

					Cipher cMsg = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cMsg.init(Cipher.DECRYPT_MODE, unwrappedKey);

					String msg = (String) inStream.readObject();
					String msgDec = new String(cMsg.doFinal(Base64.getDecoder().decode(msg)));
					System.out.println(msgDec);
				}

				recv = (String) inStream.readObject();
				System.out.println(recv);
				if(!recv.contains("=")){
					System.out.println((String) inStream.readObject());
				}
			} else {
				System.out.println("Comando errado!");
			}

		} catch (Exception e) {
			e.printStackTrace();
			sair();
		}
	}

	private void defaultComm(String[] args, int n) {
		try {
			for(int i = 0; i<n; i++) {
				outStream.writeObject(args[i]);
			}
			System.out.println(inStream.readObject());
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			sair();
		}
	}

	private void addOrRemoveU(String[] cmd) {
		try {
			outStream.writeObject(cmd[0]);
			outStream.writeObject(cmd[1]);
			outStream.writeObject(cmd[2]);

			Object obj = inStream.readObject();
			if (!(obj instanceof Integer)){
				System.out.println((String) obj);
				return;
			}

			int id = (Integer) obj;
			id++;

			ArrayList<String> members = new ArrayList<>();

			String recv = null;
			while(!(recv = (String) inStream.readObject()).equals("")){
				members.add(recv);
			}

			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey sk = kg.generateKey();

			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream fis = new FileInputStream(truststore);
			ks.load(fis, null);

			for (String member : members) {
				Certificate cert = (Certificate) ks.getCertificate(member);

				Cipher c = Cipher.getInstance("RSA");
				c.init(Cipher.WRAP_MODE, cert);

				byte[] wrappedKey = c.wrap(sk);

				outStream.writeObject(member+" "+id+":"+Base64.getEncoder().withoutPadding().encodeToString(wrappedKey));
			}

			outStream.writeObject("");

			System.out.println((String) inStream.readObject());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void send(String photo_path){
		File photo = new File(photo_path);

		try{
			System.out.println(photo.toPath());
			byte[] content = Files.readAllBytes(photo.toPath());
			outStream.writeObject(content);
		} catch(IOException e) {
			e.printStackTrace();
		}
	}

	private void receive(int n){
		try {
			for(int i = 0; i < n; i++) {

				String photo = (String) inStream.readObject();

				File fout = new File("users"+fs+clientID+fs+"w "+photo);

				fout.createNewFile();

				byte[] content = (byte[]) inStream.readObject();
				Files.write(fout.toPath(), content);

				System.out.println(inStream.readObject());
			}

		} catch(ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}
	}

	private Boolean autenticar(String user) {
		Boolean res = false;
		try {
			outStream.writeObject(user);

			long nonce = (long) inStream.readObject();

			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream fis = new FileInputStream(keystore);
			ks.load(fis, ksPassword.toCharArray());
			PrivateKey key = (PrivateKey) ks.getKey(clientID, ksPassword.toCharArray());

			Signature s = Signature.getInstance("MD5withRSA");

			SignedObject obj = new SignedObject(nonce, key, s);

			String resposta = (String) inStream.readObject();

			if(!resposta.equals("")){
				System.out.println(resposta);
				return res;
			}

			outStream.writeObject(obj);

			resposta = (String) inStream.readObject();

			System.out.println(resposta);

			if (resposta.equals("Autenticacao mal sucedida")) {
				return res;
			}

		} catch(Exception e) {
			e.printStackTrace();
			sair();
		}

		return !res;
	}

	private void sair() {
		try {
			inStream.close();
			outStream.close();
			ss.close();
		} catch(IOException e){
			e.printStackTrace();
		}
	}

}
