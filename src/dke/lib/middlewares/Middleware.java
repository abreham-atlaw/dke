package dke.lib.middlewares;

import java.io.IOException;
import java.util.*;


public interface Middleware{
	
	public String onSend(Map<String, Object> context, String msg) throws IOException;

	public String onRecv(Map<String, Object> context, String msg) throws IOException;

	public void onInit(Map<String, Object> context) throws IOException;

}
