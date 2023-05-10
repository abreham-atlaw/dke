package dke.test.lib.security.keyexchanges;

import java.net.*;
import java.io.*;

import dke.lib.security.keyexchanges.DiffieHelmanKeyExchange;
import dke.lib.utils.Logging;


class DiffieHelmanKeyExchangeTest{

	public static int KEY_LENGTH = 128;
	public static String HOST = "127.0.0.1";
	public static int PORT = 4444;
	
	
	public static void main(String[] args) throws InterruptedException{

		Thread clientThread = new ClientThread();
		Thread serverThread = new ServerThread();
		System.out.println("[+]Starting ServerThread...");
		serverThread.start();
		
		Thread.sleep(10);
		System.out.println("[+]Starting ClientThread...");
		clientThread.start();

	}
}

class ClientThread extends Thread{

	public void run(){
		try (Socket socket = new Socket(
				DiffieHelmanKeyExchangeTest.HOST,
				DiffieHelmanKeyExchangeTest.PORT
		)) {
			DiffieHelmanKeyExchange exchange = new DiffieHelmanKeyExchange(
					DiffieHelmanKeyExchangeTest.KEY_LENGTH
			);
			byte[] key = exchange.exchange(socket.getInputStream(), socket.getOutputStream(), true);
			System.out.printf("[+]Client: %s\n", Logging.formatByteArray(key));
		} catch (IOException ex) {
			System.out.println("[-]ClientThread: Test Failed with msg: " + ex.getMessage());
		}

	}
}

class ServerThread extends Thread{

	public void run(){

		try(ServerSocket ss = new ServerSocket(DiffieHelmanKeyExchangeTest.PORT)){
			Socket socket = ss.accept();
			DiffieHelmanKeyExchange exchange = new DiffieHelmanKeyExchange();
			byte[] key = exchange.exchange(socket.getInputStream(), socket.getOutputStream(), false);
			System.out.printf("[+]Server: %s\n", Logging.formatByteArray(key));
		}
		catch(IOException ex){
			System.out.println("[-]ServerThread: Test Failed with msg: "+ex.getMessage());
		}
	}
}
			
