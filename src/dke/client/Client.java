package dke.client;

import dke.lib.Session;
import dke.lib.middlewares.AESMiddleware;
import dke.lib.middlewares.DiffieHelmanKeyExchangeMiddleware;

import java.io.*;
import java.net.*;


public class Client{
    
    private static final int PORT=1234;
	private static InetAddress HOST;
	private static final int KEY_LENGTH = 128;

	private static Session initializeSession() throws IOException{
		HOST = InetAddress.getLocalHost();
		Socket socket = new Socket(HOST, PORT);
		Session session = new Session(socket);
		session.addMiddleware(new DiffieHelmanKeyExchangeMiddleware(KEY_LENGTH));
		session.addMiddleware(new AESMiddleware());
		session.start();
		return session;
	}

	private static void chat(Session session) throws IOException{
		BufferedReader userentry = new BufferedReader(new InputStreamReader(System.in));
		String message, response;
		do{
			System.out.print("Enter message:");
			message=userentry.readLine();
//			message = "Hello";
			session.send(message);
			response=session.read();
			System.out.println("\nSERVER>" + response);
		} while(!message.equals("close"));
	}

    public static void main(String[] args) throws IOException {
		Session session = initializeSession();
		chat(session);
    }
}
