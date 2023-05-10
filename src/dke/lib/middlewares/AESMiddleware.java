package dke.lib.middlewares;

import dke.lib.security.symmetric.AES;
import dke.lib.security.symmetric.SymmetricEncryption;

import java.io.IOException;
import java.util.Map;

public class AESMiddleware extends SymmetricEncryptionMiddleware{

	@Override
	protected SymmetricEncryption onCreateEncryption(byte[] key) {
		return new AES(key, false);
	}

}
