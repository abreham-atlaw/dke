package dke.lib.middlewares;

import dke.lib.security.keyexchanges.KeyExchange;
import dke.lib.security.symmetric.SymmetricEncryption;
import dke.lib.utils.Logging;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public abstract class SymmetricEncryptionMiddleware implements Middleware{

	private SymmetricEncryption encryption;

	public SymmetricEncryptionMiddleware(){

	}

	public SymmetricEncryptionMiddleware(byte[] key){
		encryption = onCreateEncryption(key);
	}

	protected abstract SymmetricEncryption onCreateEncryption(byte[] key);

	protected String encode(byte[] msg){
		StringBuilder stringBuilder = new StringBuilder();
		for(byte b: msg){
			stringBuilder.append((char)b);
		}
		return stringBuilder.toString();
	}

	protected byte[] decode(String msg){
		byte[] bytes = new byte[msg.length()];
		for(int i=0; i<bytes.length; i++){
			bytes[i] = (byte)msg.charAt(i);
		}
		return bytes;
	}

	@Override
	public String onSend(Map<String, Object> context, String msg) throws IOException {
		return encode(encryption.encrypt(decode(msg)));
	}

	@Override
	public String onRecv(Map<String, Object> context, String msg) throws IOException {
		return encode(encryption.decrypt(decode(msg)));
	}

	@Override
	public void onInit(Map<String, Object> context) throws IOException {
		if(encryption != null)
			return;

		byte[] key = (byte[]) context.get(KeyExchange.CTX_KEY_KEY);
		if(key == null){
			throw new KeyNotSetException("Key not found. Make sure a KeyExchange Middleware is placed before SymmetricEncryption");
		}
		System.out.printf("SymmetricEncryption: Found key: %s\n", Logging.formatByteArray(key));
		encryption = onCreateEncryption(key);
	}

	public static class KeyNotSetException extends RuntimeException{
		public KeyNotSetException(String msg){
			super(msg);
		}
	}
}
