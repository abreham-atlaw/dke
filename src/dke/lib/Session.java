package dke.lib;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

import dke.lib.middlewares.Middleware;
import dke.lib.utils.Logging;

public class Session{

	public static final String CTX_SESSION_KEY = "session";

	private final Socket socket;
	private final ArrayList<Middleware> middlewares = new ArrayList<>();
	private BufferedReader reader;
	private PrintWriter writer;
	private InputStream inputStream;
	private OutputStream outputStream;
	private final Map<String, Object> context = new HashMap<>();

	public Session(Socket socket){
		this.socket = socket;

	}

	public void addMiddleware(Middleware middleware){
		middlewares.add(middleware);
	}

	public InputStream getInputStream() {
		return inputStream;
	}

	public OutputStream getOutputStream() {
		return outputStream;
	}

	public void send(String msg) throws IOException{
		for(Middleware middleware: middlewares){
			msg = middleware.onSend(context, msg);
		}
		writer.println(msg);
	}
	
	public String read() throws IOException{
		String msg = reader.readLine();
		for(Middleware middleware: middlewares) {
			msg = middleware.onRecv(context, msg);
		}
		return msg;
	}

	public void start() throws IOException{
		this.inputStream = socket.getInputStream();
		this.outputStream = socket.getOutputStream();
		this.context.put(CTX_SESSION_KEY, this);
		for(Middleware middleware: middlewares){
			middleware.onInit(context);
		}
		this.reader = new BufferedReader(new InputStreamReader(this.inputStream));
		this.writer = new PrintWriter(this.outputStream, true);

	}
}
