package server;
import java.io.IOException;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;


public class SeiTchizServer {

	public static void main(String[] args) {

		System.out.println("servidor: main");
		SeiTchizServer server = new SeiTchizServer();

		if (args.length < 3) {
			System.out.println("Tem de usar os argumentos SeiTchizServer <port> <keystore> <keystore-password>");
			System.exit(-1);
		}

		String a = args[1];
		String b = args[2];
		System.setProperty("javax.net.ssl.keyStore", a);
		System.setProperty("javax.net.ssl.keyStorePassword", b);

		int porto = Integer.parseInt(args[0]);

		server.startServer(porto, a, b);
	}

	public void startServer (int porto, String keystore, String ksPassword){

		SSLServerSocket ss = null;

		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			ss = (SSLServerSocket) ssf.createServerSocket(porto);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}


		while(true) {
			try {
				ServerThread newServerThread = new ServerThread(ss.accept(), keystore, ksPassword);
				newServerThread.start();
	    }
	    catch (IOException e) {
	        e.printStackTrace();
	    }

		}
		//sSoc.close();
	}
}
