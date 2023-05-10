package dke.server;

import dke.lib.Session;
import dke.lib.middlewares.AESMiddleware;
import dke.lib.middlewares.DiffieHelmanKeyExchangeMiddleware;

import java.io.*;
import java.net.*;


public class Server {
    
    private static final int PORT=1234;


    public static void listenSocket() throws IOException{
		ServerSocket serverSocket = new ServerSocket(PORT);
		while(true){
			Socket socket = serverSocket.accept();
			System.out.println("[+]New Connection. Starting Thread...");
			ServerThread thread = new ServerThread(socket);
			thread.start();
		}
    }

    public static void main(String[] args) throws IOException {
		System.out.println("Opening port.....");
		listenSocket();
    }


	static class ServerThread extends Thread{

		Socket socket;
		public ServerThread(Socket socket){
			this.socket = socket;
		}

		private Session initializeSession() throws IOException{
			Session session = new Session(socket);
			session.addMiddleware(new DiffieHelmanKeyExchangeMiddleware());
			session.addMiddleware(new AESMiddleware());
			session.start();
			return session;
		}

		private void echo(Session session) throws IOException{

			int numMessages=0;
			String message;
			do{
				message = session.read();
				System.out.printf("Message Received: %s\n", message);
				numMessages++;
				session.send("Message" + numMessages+ ":" + message);
			} while(!message.equals("close"));

		}

		@Override
		public void run() {
			Session session;
			try{
				session = initializeSession();
				echo(session);
			}
			catch(IOException ex){
				System.out.printf("[-]Session failed with ex %s\n", ex.getMessage());
			}
		}
	}
}
