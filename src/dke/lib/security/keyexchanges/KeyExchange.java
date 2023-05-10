package dke.lib.security.keyexchanges;

import java.io.*;


public interface KeyExchange{

	String CTX_KEY_KEY = "enc_key";

	public byte[] exchange(InputStream inputStream, OutputStream outputStream, boolean initialize) throws IOException;

}
