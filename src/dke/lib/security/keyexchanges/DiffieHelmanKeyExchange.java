package dke.lib.security.keyexchanges;

import java.math.*;
import java.security.*;
import java.io.*;


public class DiffieHelmanKeyExchange implements KeyExchange{
	
	private final Integer keyLength;

	public DiffieHelmanKeyExchange(Integer keyLength){
		this.keyLength = keyLength;
	}

	public DiffieHelmanKeyExchange(){
		this(null);
	}

	public byte[] exchange(InputStream inputStream, OutputStream outputStream, boolean initialize) throws IOException{

		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		PrintStream printStream = new PrintStream(outputStream);

		BigInteger q, a, x, y, yb, key;
		SecureRandom sr = new SecureRandom();
		
		int keyLength;	
		
		if(initialize){
			if(this.keyLength == null){
				throw new RuntimeException("keyLength must be set to initialize.");
			}
			keyLength = this.keyLength;
			
			q = new BigInteger(keyLength, 10, sr);
			a = new BigInteger(keyLength-1, sr);
			printStream.println(q);
			printStream.println(a);
		}	
		else{
			q = new BigInteger(reader.readLine());
			a = new BigInteger(reader.readLine());
			keyLength = q.bitLength();
		}

		x = new BigInteger(keyLength-1, sr);
		y = a.modPow(x, q);
		
		if(initialize){
			printStream.println(y);
		}
		yb = new BigInteger(reader.readLine());
		if(!initialize){
			printStream.println(y);
		}

		key = yb.modPow(x,q);
		
		return key.toByteArray();
	}
}
