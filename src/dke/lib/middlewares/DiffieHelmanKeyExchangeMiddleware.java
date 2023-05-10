package dke.lib.middlewares;

import java.io.IOException;
import java.util.*;

import dke.lib.Session;
import dke.lib.security.keyexchanges.KeyExchange;
import dke.lib.security.keyexchanges.DiffieHelmanKeyExchange;


public class DiffieHelmanKeyExchangeMiddleware extends DiffieHelmanKeyExchange implements Middleware{

	private boolean initialize = false;

	public DiffieHelmanKeyExchangeMiddleware(){
		super();
	}

	public DiffieHelmanKeyExchangeMiddleware(int keyLength){
		super(keyLength);
		this.initialize = true;
	}

	@Override
	public void onInit(Map<String, Object> context) throws IOException {
		System.out.printf("[+]DiffieHelmanKeyExchangeMiddleware: Starting Exchange(init=%b)...\n", initialize);
		Session session = (Session) context.get(Session.CTX_SESSION_KEY);
		context.put(KeyExchange.CTX_KEY_KEY, exchange(session.getInputStream(), session.getOutputStream(), initialize));
		System.out.println("[+]DiffieHelmanKeyExchangeMiddleware: Key exchange complete");
	}

	public String onSend(Map<String, Object> context, String msg) throws IOException {
		return msg;
	}
	
	public String onRecv(Map<String, Object> context, String msg) throws IOException{
		return msg;
	}
}


