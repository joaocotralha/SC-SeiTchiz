package server;
import java.io.File;
import java.nio.file.Files;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.util.Scanner;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.UUID;
import java.util.Base64;
import java.security.KeyStore;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.Certificate;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//Threads utilizadas para comunicacao com os clientes
class ServerThread extends Thread {

	private Socket socket = null;

	private String clientID;
	private String keystore;
	private String ksPassword;
	private ObjectOutputStream outStream;
	private ObjectInputStream inStream;
	private static String fs = System.getProperty("file.separator");
	private static String ls = System.lineSeparator();

	ServerThread(Socket s, String ks, String ksPass) throws IOException {
		socket = s;
		keystore = ks;
		ksPassword = ksPass;
		outStream = new ObjectOutputStream(socket.getOutputStream());
		inStream = new ObjectInputStream(socket.getInputStream());
		System.out.println("Ligacao a cliente");
	}

	public void run(){
		try {

			String user = (String)inStream.readObject();

			clientID = user;

			if(!autenticar(user)) {
				sair();
				return;
			}

			System.out.println("Cliente " + user + " autenticado com sucesso");

			while(true) {
				System.out.println("> A aguardar comando");
				String cmd = (String) inStream.readObject();

				System.out.println(cmd);

				if(cmd.equals("follow") || cmd.equals("f")) {
					String arg = (String) inStream.readObject();
					follow(arg);
				} else if(cmd.equals("unfollow") || cmd.equals("u")) {
					String arg = (String) inStream.readObject();
					unfollow(arg);
				} else if(cmd.equals("viewfollowers") || cmd.equals("v")) {
					viewfollowers();
				} else if(cmd.equals("post") || cmd.equals("p")) {
					String arg = (String) inStream.readObject();
					post(arg);
				} else if(cmd.equals("wall") || cmd.equals("w")) {
					String arg = (String) inStream.readObject();
					wall(Integer.parseInt(arg));
				} else if(cmd.equals("like") || cmd.equals("l")) {
					String arg = (String) inStream.readObject();
					like(arg);
				} else if(cmd.equals("newgroup") || cmd.equals("n")) {
					String arg = (String) inStream.readObject();
					newgroup(arg);
				} else if(cmd.equals("addu") || cmd.equals("a")) {
					String arg1 = (String) inStream.readObject();
					String arg2 = (String) inStream.readObject();
					addu(arg1, arg2);
				} else if(cmd.equals("removeu") || cmd.equals("r")) {
					String arg1 = (String) inStream.readObject();
					String arg2 = (String) inStream.readObject();
					removeu(arg1, arg2);
				} else if(cmd.equals("ginfo") || cmd.equals("g")) {
					String arg = (String) inStream.readObject();
					ginfo(arg);
				} else if(cmd.equals("msg") || cmd.equals("m")) {
					String arg = (String) inStream.readObject();
					msg(arg);
				} else if(cmd.equals("collect") || cmd.equals("c")) {
					String arg = (String) inStream.readObject();
					collect(arg);
				} else if(cmd.equals("history") || cmd.equals("h")) {
					String arg = (String) inStream.readObject();
					history(arg);
				} else if(cmd.equals("exit") || cmd.equals("e")) {
					break;
				} else {
					System.out.println("Thread com Comando errado!");
				}
			}

			sair();

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			sair();
		}
	}

	private void follow(String userID) {

		File list = new File("users"+fs+userID+fs+"followers.txt");
		try {

			if(!(new File("users"+fs+userID+fs)).exists()){
				outStream.writeObject("User especificado nao existe");
				return;
			}

			list.createNewFile();

			try(Scanner scanner = new Scanner(list)) {

				while(scanner.hasNextLine()){
					String line = scanner.nextLine();
					if(line.equals(clientID)){
						outStream.writeObject("Cliente ja segue este user");
						return;
					}
				}

				PrintWriter out = new PrintWriter(new FileWriter(list, true));
				out.append(clientID+ls);

				out.close();
			}

			File following = new File("users"+fs+clientID+fs+"following.txt");
			PrintWriter out = new PrintWriter(new FileWriter(following, true));
			out.append(userID+ls);
			out.close();

			outStream.writeObject("Operacao bem sucedida");
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void unfollow(String userID) {

		File list = new File("users"+fs+userID+fs+"followers.txt");
		File f_list = new File("users"+fs+clientID+fs+"following.txt");

		try {

			if(!(new File("users"+fs+userID+fs)).exists()){
				outStream.writeObject("User especificado nao existe");
				return;
			}

			File temp = new File("users"+fs+userID+fs+"followers_temp.txt");
			temp.createNewFile();

			Scanner scanner = new Scanner(list);
			PrintWriter out = new PrintWriter(new FileWriter(temp, true));

			Boolean notFound = true;

			while(scanner.hasNextLine()) {
			    String line = scanner.nextLine();
			    if(line.equals(clientID)) {
						notFound = false;
						continue;
					}
			    out.append(line + ls);
			}

			if(notFound){
				outStream.writeObject("Cliente nao segue este user");
				scanner.close();
				out.close();
				return;
			}

			scanner.close();
			out.close();

			list.delete();
			temp.renameTo(list);

			File f_temp = new File("users"+fs+clientID+fs+"following_temp.txt");

			scanner = new Scanner(f_list);
			out = new PrintWriter(new FileWriter(f_temp, true));
			while(scanner.hasNextLine()){
				String line = scanner.nextLine();
				if(line.equals(userID)) {
					continue;
				}
				out.append(line + ls);
			}

			scanner.close();
			out.close();

			f_list.delete();
			f_temp.renameTo(f_list);

			outStream.writeObject("Operacao bem sucedida");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void viewfollowers() {

		File list = new File("users"+fs+clientID+fs+"followers.txt");

		try {

			if(!(list.exists()) || list.length() == 0){
				outStream.writeObject("Cliente nao tem followers!");
				outStream.writeObject("");
				return;
			}

			outStream.writeObject("== Followers: =="+ls);

			Scanner scanner = new Scanner(list);
			while(scanner.hasNextLine()){
				outStream.writeObject(scanner.nextLine());
			}

			outStream.writeObject(ls+"================");
			outStream.writeObject("");
			scanner.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void post(String photo) {

    String uniqueID = UUID.randomUUID().toString();
    try {

        File fout = new File("users"+fs+clientID+fs+uniqueID+"."+photo.split("\\.")[1]);
        File fout_likes = new File("users"+fs+clientID+fs+uniqueID+".txt");
        File fout_hash = new File("users"+fs+clientID+fs+uniqueID+"hash.txt");

        fout.createNewFile();
        byte[] content = (byte[]) inStream.readObject();
        Files.write(fout.toPath(), content);

        MessageDigest md = MessageDigest.getInstance("SHA");
        byte[] hash = md.digest(content);
        fout_hash.createNewFile();
        Files.write(fout_hash.toPath(), hash);

        fout_likes.createNewFile();
        PrintWriter out = new PrintWriter(new FileWriter(fout_likes, false));
        out.append("0");
        out.close();
    } catch(ClassNotFoundException | IOException | NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
  }

	private void wall(int n) {
		File following = new File("users"+fs+clientID+fs+"following.txt");

		try {
			if(!following.exists()) {
				outStream.writeObject("Cliente nao segue ninguem");
				return;
			}

			int count = 0;

			ArrayList<String> users = new ArrayList<String>();
			ArrayList<File> photos = new ArrayList<File>();

			Scanner scanner = new Scanner(following);
			while(scanner.hasNextLine()){
				users.add(scanner.nextLine());
			}

			scanner.close();

			for(String u : users){
				File current = new File("users"+fs+u+fs);

				File[] files = current.listFiles();
				for(File f : files) {
					String name = f.getName();
					if(name.contains("w ") || name.split("\\.")[1].equals("txt") || name.split("\\.")[1].equals("client")) {
						continue;
					}
					File photo = new File("users"+fs+u+fs+name.split("\\.")[0]+"hash.txt");

          MessageDigest md = MessageDigest.getInstance("SHA");
          byte[] content = Files.readAllBytes(f.toPath());
          byte[] original = Files.readAllBytes(photo.toPath());

          if(MessageDigest.isEqual(md.digest(content), original)) {
              photos.add(f);
              count++;
          } else {
						outStream.writeObject("Imagem corrompida");
						return;
          }
      	}
			}

			photos.sort(new FileAgeComparator1());

			if(count > n) {
				count = n;
			} else if (count == 0) {
				outStream.writeObject("Nao existem fotografias!");
				return;
			}

			ArrayList<File> wall = new ArrayList<File>();
			for(int i = 0; i< count; i++) {
	    	wall.add(photos.get(i));
			}

			outStream.writeObject(count);

			outStream.writeObject("================ Wall: ================");

			for(File w : wall){
				outStream.writeObject(w.getName());

				byte[] content = Files.readAllBytes(w.toPath());
				outStream.writeObject(content);

				int index = w.toPath().toString().lastIndexOf('.');
				File likes = new File(w.toPath().toString().substring(0, index)+".txt");

				scanner = new Scanner(likes);
				outStream.writeObject(w.getName().split("\\.")[0]+" "+scanner.nextLine());
				scanner.close();
			}

			outStream.writeObject("=======================================");

		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	private void like(String photoID) {

		File a = new File("users"+fs);

		try {
			File[] allUsers = a.listFiles();

			File photo = null;

			for(File fotos : allUsers) {
				File likes = new File("users"+fs+fotos.getName()+fs+photoID+".txt");
				if(likes.exists()) {
					photo = likes;
					break;
				}
			}

			if(photo != null) {

				int nLikes = 0;
				Scanner scan = new Scanner(photo);
				if(scan.hasNextLine()) {
					nLikes = Integer.valueOf(scan.nextLine());
				}
				scan.close();

				PrintWriter out = new PrintWriter(new FileWriter(photo, false));
				out.append(String.valueOf(nLikes + 1));
				outStream.writeObject("Operacao bem sucedida");
				out.close();
			} else {
				outStream.writeObject("A fotografia indicada nao existe");
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void newgroup(String groupID) {

		String path = "groups"+fs+groupID+fs+clientID+".txt";

		File group = new File("groups"+fs+groupID+fs+"members.txt");
		File owner = new File("users"+fs+clientID+fs+"owner.txt");
		File key = new File("groups"+fs+groupID+fs+"key.txt");
		File key_list = new File(path);

		try {

			String recv = (String) inStream.readObject();

			File newdir = new File("groups"+fs+groupID+fs);
			if(!newdir.mkdirs())	{
				outStream.writeObject("Grupo ja existente");
				return;
			}

			PrintWriter out_g = new PrintWriter(new FileWriter(group, true));
			PrintWriter out_o = new PrintWriter(new FileWriter(owner, true));
			PrintWriter out_k = new PrintWriter(new FileWriter(key, false));
			PrintWriter out_kl = new PrintWriter(new FileWriter(key_list, true));

			out_g.append(clientID+" "+path+ls);
			out_o.append(groupID + ls);
			out_k.append(0+":"+recv+ls);
			out_kl.append(0+":"+recv+ls);

			outStream.writeObject("Operacao bem sucedida");

			out_g.close();
			out_o.close();
			out_k.close();
			out_kl.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void addu(String userID, String groupID) {

		File group = new File("groups"+fs+groupID+fs+"members.txt");
		File member = new File("users"+fs+userID+fs+"member.txt");


		try {

			if(!(new File("groups"+fs+groupID+fs)).exists()){
				outStream.writeObject("Grupo nao existente");
				return;
			}

			if(!(new File("users"+fs+userID)).exists()){
				outStream.writeObject("Utilizador nao existente");
				return;
			}

			if(clientID.equals(userID)){
				outStream.writeObject("Cliente nao pode adicionar-se a si mesmo");
				return;
			}

			Scanner scanner = new Scanner(group);
			if(scanner.hasNextLine() && !scanner.nextLine().split(" ")[0].equals(clientID)) {
				outStream.writeObject("Cliente nao e dono do grupo "+groupID);
				scanner.close();
				return;
			}

			while(scanner.hasNextLine()){
				if(scanner.nextLine().equals(userID)){
					outStream.writeObject("Utilizador ja faz parte do grupo");
					scanner.close();
					return;
				}
			}

			scanner.close();

			PrintWriter out = new PrintWriter(new FileWriter(group, true));
			out.append(userID+" "+"groups"+fs+groupID+fs+userID+".txt");
			out.close();

			updateKeys(userID, groupID);

			outStream.writeObject("Operacao bem sucedida");

			member.createNewFile();
			PrintWriter out_m = new PrintWriter(new FileWriter(member, true));
			out_m.append(groupID+ls);
			out_m.close();

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void removeu(String userID, String groupID) {

		File group = new File("groups"+fs+groupID+fs+"members.txt");
		File temp_g = new File("groups"+fs+groupID+fs+"members_temp.txt");

		try {

			if(!(new File("groups"+fs+groupID+fs)).exists()){
				outStream.writeObject("Grupo nao existente");
				return;
			}

			if(clientID.equals(userID)){
				outStream.writeObject("Cliente nao pode remover-se a si mesmo");
				return;
			}

			Scanner scanner = new Scanner(group);
			Boolean in_group = false;

			temp_g.createNewFile();

			String line = null;
			if(scanner.hasNextLine() && !(line = scanner.nextLine()).split(" ")[0].equals(clientID)) {
				outStream.writeObject("Cliente nao e dono do grupo "+groupID);
				scanner.close();
				return;
			}
			PrintWriter out = new PrintWriter(new FileWriter(temp_g, true));
			out.append(line + ls);

			while(scanner.hasNextLine()) {
			    line = scanner.nextLine();
					if(line.split(" ")[0].equals(userID)){
						in_group = true;
						continue;
					}
			    out.append(line + ls);
			}
			scanner.close();
			out.close();

			if(!in_group){
				outStream.writeObject("Utilizador nao faz parte do grupo");
				temp_g.delete();
				return;
			}

			group.delete();
			temp_g.renameTo(group);

			updateKeys(userID, groupID);

			File member = new File("users"+fs+userID+fs+"member.txt");
			File temp_m = new File("users"+fs+userID+fs+"member_temp.txt");

			scanner = new Scanner(member);
			out = new PrintWriter(new FileWriter(temp_m, true));

			temp_m.createNewFile();

			while(scanner.hasNextLine()){
				line = scanner.nextLine();
				if(line.equals(groupID)){
					continue;
				}
				out.append(line + ls);
			}

			outStream.writeObject("Operacao bem sucedida");

			scanner.close();
			out.close();

			member.delete();
			temp_m.renameTo(member);

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void ginfo(String groupID){

		if(groupID.equals("")){
			ginfo_aux();
			return;
		}

		File member = new File("users"+fs+clientID+fs+"member.txt");
		File group = new File("groups"+fs+groupID+fs+"members.txt");
		Boolean is_member = false;

		try {

			if(!(new File("groups"+fs+groupID+fs)).exists()){
				outStream.writeObject("Nao existe este grupo");
				outStream.writeObject("");
				return;
			}

			if(member.exists()) {
				Scanner sc_member = new Scanner(member);
				while(sc_member.hasNextLine()){
					if(sc_member.nextLine().equals(groupID)){
						is_member = true;
					}
				}
				sc_member.close();
			}

			Scanner sc_group = new Scanner(group);
			String line = null;

			if(!((sc_group.hasNextLine() &&
					(line = sc_group.nextLine().split(" ")[0]).equals(clientID)) || is_member)) {
				outStream.writeObject("Cliente nao e dono ou membro do grupo " + groupID);
				outStream.writeObject("");
				sc_group.close();
				return;
			}

			outStream.writeObject(ls+"Grupo: "+groupID+" | Dono: "+line);
			outStream.writeObject("===== Membros: ====="+ls);

			if(!sc_group.hasNextLine()){
				outStream.writeObject("   Nao ha membros   ");
			} else {
				while(sc_group.hasNextLine()){
					outStream.writeObject(sc_group.nextLine().split(" ")[0]);
				}
			}

			outStream.writeObject(ls+"====================");
			outStream.writeObject("");

			sc_group.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void ginfo_aux(){

		File owner = new File("users"+fs+clientID+fs+"owner.txt");
		File member = new File("users"+fs+clientID+fs+"member.txt");

		try {

			if(!(owner.exists()) || owner.length() == 0){
				outStream.writeObject("Cliente nao e dono de nenhum grupo!");
			} else {

				Scanner sc_owner = new Scanner(owner);

				outStream.writeObject("== Dono de: =="+ls);
				while(sc_owner.hasNextLine()){
					outStream.writeObject(sc_owner.nextLine());
				}

				outStream.writeObject(ls+"==============");
				sc_owner.close();
			}

			if(!(member.exists()) || member.length() == 0){
				outStream.writeObject("Cliente nao e membro de nenhum grupo!");
			} else {
				Scanner sc_member = new Scanner(member);
				outStream.writeObject("= Membro de: ="+ls);

				while(sc_member.hasNextLine()){
					outStream.writeObject(sc_member.nextLine().split(" ")[0]);
				}
				outStream.writeObject(ls+"==============");
				sc_member.close();
			}

			outStream.writeObject("");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void msg(String groupID) {

		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter dtf1 = DateTimeFormatter.ofPattern("yyyy-MM-dd HH.mm.ss");

		try {
			if(!(new File("groups"+fs+groupID+fs)).exists()){
				outStream.writeObject("Grupo nao existente");
				return;
			}

			File grupo = new File("groups"+fs+groupID+fs+"members.txt");
			File key_list = null;

			Scanner scanner = new Scanner(grupo);

			boolean found = false;
			ArrayList<String> list = new ArrayList<String>();

			while(scanner.hasNextLine()){
				String[] line = scanner.nextLine().split(" ");
				list.add(line[0]);
				if(line[0].equals(clientID)){
					found = true;
					key_list = new File("groups"+fs+groupID+fs+clientID+".txt");
				}
			}

			scanner.close();

			if(!found) {
				outStream.writeObject("Utilizador nao pertence ao grupo");
				return;
			}

			scanner = new Scanner(key_list);
			String ukey = null;
			while(scanner.hasNextLine()){
				ukey = scanner.nextLine();
			}
			scanner.close();

			outStream.writeObject(ukey);

			String id = ukey.substring(0,ukey.indexOf(":"));
			String fileName = id+" "+dtf1.format(now)+".txt";
			File inbox = new File("groups"+fs+groupID+fs+fileName);

			String msg = (String) inStream.readObject();
			PrintWriter out = new PrintWriter(new FileWriter(inbox, true));
			out.append(msg);
			out.close();

			for(String m : list) {
				File userInbox = new File("users"+fs+m+fs+groupID+"-"+fileName);
				PrintWriter outUser = new PrintWriter(new FileWriter(userInbox, true));
				userInbox.createNewFile();
				outUser.append(msg);
				outUser.close();
			}

			outStream.writeObject("Mensagem enviada");

		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}


	}

	private void collect(String groupID) {

		File grupo = new File("groups"+fs+groupID+fs+"members.txt");
		File user = new File("users"+fs+clientID+fs);
		File key_list = null;

		try {
			if(!(new File("groups"+fs+groupID+fs)).exists()) {
				outStream.writeObject("Grupo nao existente");
				return;
			}

			Scanner scanner = new Scanner(grupo);

			boolean found = false;

			while(scanner.hasNextLine()){
				String line = scanner.nextLine();
				if(line.split(" ")[0].equals(clientID)){
					found = true;
					key_list = new File(line.split(" ")[1]);
					break;
				}
			}
			scanner.close();

			if(!found) {
				outStream.writeObject("Utilizador nao pertence ao grupo");
				return;
			}

			//ler todas msgs no diretorio do user
			outStream.writeObject("== Mensagens nao lidas: ==");

			int count = 0;

			String key = null;
			Scanner key_scanner = new Scanner(key_list);

			File[] dirList = user.listFiles();
			Arrays.sort(dirList, new FileAgeComparator2());

	    for (File f : dirList) {

				String name = f.getName();
				Pattern p = Pattern.compile("^.+-\\d+\\s\\d\\d\\d\\d-\\d\\d-\\d\\d\\s\\d\\d\\.\\d\\d\\.\\d\\d\\.txt$");
				Matcher matcher = p.matcher(name);
				if(!matcher.matches() && !name.split("-")[0].equals(groupID)) {
					continue;
				}

				count++;

				int s = name.indexOf('-')+1;
				int e = name.indexOf(' ');
				String currID = name.substring(s, e);

				while(key_scanner.hasNextLine()){
					key = key_scanner.nextLine();
					if (key.split(":")[0].equals(currID)){
						break;
					}
				}

				outStream.writeObject(key);

				scanner = new Scanner(f);
				while(scanner.hasNextLine()){
					outStream.writeObject(scanner.nextLine());
				}
				scanner.close();
				f.delete();
			}
			key_scanner.close();

			outStream.writeObject("");

			if(count == 0) {
				outStream.writeObject("Nao ha mensagens por ler");
			}
			outStream.writeObject("==========================");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void history(String groupID){

		DateTimeFormatter dtf1 = DateTimeFormatter.ofPattern("yyyy-MM-dd HH.mm.ss");

		File groupDir = new File("groups"+fs+groupID+fs);
		File grupo = new File("groups"+fs+groupID+fs+"members.txt");
		File user = new File("users"+fs+clientID+fs);
		File key_list = null;

		try {

			if(!groupDir.exists()) {
				outStream.writeObject("Grupo nao existente");
				return;
			}

			boolean found = false;
			Scanner scanner = new Scanner(grupo);
			while(scanner.hasNextLine()){
				String[] line = scanner.nextLine().split(" ");
				if(line[0].equals(clientID)){
					found = true;
					key_list = new File(line[1]);
					break;
				}
			}
			scanner.close();

			if(!found) {
				outStream.writeObject("Utilizador nao pertence ao grupo");
				return;
			}

			ArrayList<File> dirListU = new ArrayList<File>(Arrays.asList(user.listFiles()));
			ArrayList<File> remove = new ArrayList<File>();
			for(File f: dirListU) {
				String name = f.getName();
				Pattern p = Pattern.compile("^.+-\\d+\\s\\d\\d\\d\\d-\\d\\d-\\d\\d\\s\\d\\d\\.\\d\\d\\.\\d\\d\\.txt$");
				Matcher matcher = p.matcher(name);
				if(!matcher.matches() && !name.split("-")[0].equals(groupID)) {
					remove.add(f);
				}
			}
			dirListU.removeAll(remove);
			dirListU.sort(new FileAgeComparator2());

			LocalDateTime earliest = LocalDateTime.MAX;
			if(dirListU.size() > 0) {
				String n = dirListU.get(0).getName();
				int s = n.indexOf(' ')+1;
				int t = n.lastIndexOf('.');
				earliest = LocalDateTime.parse(n.substring(s, t), dtf1);
			}

			File[] dirList = groupDir.listFiles();
			Arrays.sort(dirList, new FileAgeComparator2());

			int count = 0;
			int keyID = 0;
			String key = null;
			Scanner key_scanner = new Scanner(key_list);

			outStream.writeObject("== Historico de mensagens: ==");
			for (File f: dirList) {

				String name = f.getName();

				Pattern p = Pattern.compile("^\\d+\\s\\d\\d\\d\\d-\\d\\d-\\d\\d\\s\\d\\d\\.\\d\\d\\.\\d\\d\\.txt$");
				Matcher matcher = p.matcher(name);
				if(!matcher.matches()) {
					continue;
				}

				int currID = Integer.parseInt(name.substring(0,name.indexOf(" ")));

				while(keyID < currID && key_scanner.hasNextLine()){
					key = key_scanner.nextLine();
					keyID = Integer.parseInt(key.split(":")[0]);
				}

				int s = name.indexOf(' ')+1;
				int t = name.lastIndexOf('.');
				LocalDateTime currDate = LocalDateTime.parse(name.substring(s,t), dtf1);

				if(keyID > currID){
					continue;
				} else if((keyID < currID && !scanner.hasNextLine()) ||
									currDate.compareTo(earliest) >= 0) {
					break;
				}

				count++;
				outStream.writeObject(key);

				scanner = new Scanner(f);
				while(scanner.hasNextLine()){
					outStream.writeObject(scanner.nextLine());
				}
				scanner.close();

			}
			key_scanner.close();

			outStream.writeObject("");

			if(count == 0) {
				outStream.writeObject("User ainda nao leu nenhuma mensagem");
			}
			outStream.writeObject("=============================");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void updateKeys(String userID, String groupID) {

		File group = new File("groups"+fs+groupID+fs+"members.txt");
		File key = new File("groups"+fs+groupID+fs+"key.txt");

		try {
			Scanner scanner = new Scanner(key);
			int id = 0;

			if(scanner.hasNextLine()){
				id = Integer.parseInt(scanner.nextLine().split(":")[0]);
			}
			scanner.close();

			outStream.writeObject(id);

			scanner = new Scanner(group);
			while(scanner.hasNextLine()){
				String line = scanner.nextLine().split(" ")[0];
				outStream.writeObject(line);
			}

			outStream.writeObject("");
			scanner.close();

			String recv = null;
			while(!(recv = (String) inStream.readObject()).equals("")){
				String[] pair = recv.split(" ");
				String path = "groups"+fs+groupID+fs+pair[0]+".txt";

				File key_list = new File(path);
				PrintWriter out_kl = new PrintWriter(new FileWriter(key_list, true));
				out_kl.append(pair[1]+ls);
				out_kl.close();

				if(pair[0].equals(clientID)) {
					PrintWriter out_k = new PrintWriter(new FileWriter(key, false));
					out_k.append(pair[1]+ls);
					out_k.close();
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private Boolean autenticar(String user){

		Boolean res = false;
		Boolean found = false;

		File file = new File("users.txt");

		Key seckey = null;

		try {
			if (user.length() == 0){
				outStream.writeObject("Por favor introduza um clientID");
				return res;
			}

			KeyStore serverKS = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream fis = new FileInputStream(keystore);
			serverKS.load(fis, ksPassword.toCharArray());

			if((new File("users.cif")).exists()) {
			//Obter chave codificada
		    ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keyfile.txt"));
		    byte[] wrappedKey = Base64.getDecoder().decode((String) ois.readObject());
				ois.close();

				Cipher kDec = Cipher.getInstance("RSA");

				Key serverpk = serverKS.getKey("myServer", ksPassword.toCharArray());

				kDec.init(Cipher.UNWRAP_MODE, serverpk);
				seckey = kDec.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

				Cipher cDec = Cipher.getInstance("AES/ECB/PKCS5Padding");
		    cDec.init(Cipher.DECRYPT_MODE, seckey);

		    FileInputStream fisDec;
		    fisDec = new FileInputStream("users.cif");
		    CipherInputStream cis;
		    cis = new CipherInputStream(fisDec, cDec);

		    FileOutputStream fosDec;
		    fosDec = new FileOutputStream("users.txt");

		    byte[] b1 = new byte[16];

		    int j = cis.read(b1);
		    while(j != -1) {
		    	fosDec.write(b1, 0, j);
		    	j = cis.read(b1);
		    }

		    cis.close();
		    fisDec.close();
		    fosDec.close();

			} else {
				file.createNewFile();
				KeyGenerator kg = KeyGenerator.getInstance("AES");
				kg.init(128);
				seckey = kg.generateKey();

				Cipher kEnc = Cipher.getInstance("RSA");

				Certificate cert = serverKS.getCertificate("myServer");

				kEnc.init(Cipher.WRAP_MODE, cert);
				byte[] wrappedKey = kEnc.wrap(seckey);

		    FileOutputStream kos = new FileOutputStream("keyfile.txt");
		    ObjectOutputStream oos = new ObjectOutputStream(kos);
		    oos.writeObject(Base64.getEncoder().withoutPadding().encodeToString(wrappedKey));
		    oos.close();
		    kos.close();
			}

			Scanner scanner = new Scanner(file);
			while(scanner.hasNextLine()){
				String line = scanner.nextLine();
				String[] data = line.split(" ");
				if(data[0].equals(user)){
					found = true;
					break;
				}
			}

			scanner.close();

			SecureRandom sr = new SecureRandom();
			byte[] rndBytes = new byte[8];
			sr.nextBytes(rndBytes);

			long nonce = ByteBuffer.wrap(rndBytes).getLong();

			outStream.writeObject(nonce);

			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			fis = new FileInputStream("truststore.client");
			ks.load(fis, null);

			if(!ks.containsAlias(clientID)){
				outStream.writeObject("User nao tem certificado na truststore");
				return res;
			}

			outStream.writeObject("");

			Certificate cert = (Certificate) ks.getCertificate(user);
			PublicKey pk = cert.getPublicKey();

			Signature s = Signature.getInstance("MD5withRSA");

			SignedObject resposta = (SignedObject) inStream.readObject();

			if(resposta.verify(pk, s) && resposta.getObject().equals(nonce)){
				res = true;
				outStream.writeObject("Autenticacao bem sucedida");
			} else {
				outStream.writeObject("Autenticacao mal sucedida");
			}

			//registo
			if(!found && res){
				String key = Base64.getEncoder().encodeToString(pk.getEncoded());
				String line = user+" "+key+ls;

				PrintWriter out = new PrintWriter(new FileWriter(file, true));
				out.append(line);
				out.close();

				String dir = "users"+fs+user+fs;
				File newdir = new File(dir);
				newdir.mkdirs();
			}

			cert = serverKS.getCertificate("myServer");
			Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    c.init(Cipher.ENCRYPT_MODE, seckey);

	    FileInputStream fisEnc;
	    FileOutputStream fos;
	    CipherOutputStream cos;

	    fisEnc = new FileInputStream("users.txt");
	    fos = new FileOutputStream("users.cif");

	    cos = new CipherOutputStream(fos, c);
	    byte[] b = new byte[16];
	    int i = fisEnc.read(b);
	    while (i != -1) {
	        cos.write(b, 0, i);
	        i = fisEnc.read(b);
	    }

	    cos.close();
	    fisEnc.close();
	    fos.close();
			file.delete();
		} catch (Exception e1) {
			e1.printStackTrace();
			sair();
		}

		return res;
	}

	private void sair() {
		try {
			outStream.close();
			inStream.close();
			socket.close();
		} catch(IOException e) {
			e.printStackTrace();
		}
		System.out.println("Cliente desconectado");
	}

	private class FileAgeComparator1 implements Comparator<File> {
		public int compare(File f1, File f2){
			return Long.valueOf(f2.lastModified()).compareTo(f1.lastModified());
		}
	}

	private class FileAgeComparator2 implements Comparator<File> {
		public int compare(File f1, File f2){
			return Long.valueOf(f1.lastModified()).compareTo(f2.lastModified());
		}
	}

}
