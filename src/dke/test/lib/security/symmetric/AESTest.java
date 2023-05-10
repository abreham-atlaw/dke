package dke.test.lib.security.symmetric;


import java.util.Random;
import java.util.Arrays;

import dke.lib.security.symmetric.AES;


class AESTest{

	private static final byte[] KEY = new byte[]{ 37, -25, -76, 3, 82, -60, -100, 101, -89, 43, -44, -74, 100, 34, -121, -101 };
	private static final byte[] MSG = new byte[]{ -30, 36, 110, -107, -56, -124, 43, -35, -84, -116, -16, -8, -83, 68, -75, 86, -122, 59, 61, 112, -68, -119, 62, 98, -64, -126, 41, -67, -3, -47, -46};
	private static void testEncryptDecrypt(){
		AES aes = new AES(KEY, true);
		System.out.println("[+]Encrypting...");
		byte[] encrypted = aes.encrypt(MSG);
		System.out.println("[+]Decrypting...");

		AES dAes = new AES(KEY, true);
		byte[] decrypted = dAes.decrypt(encrypted);
		assert Arrays.equals(decrypted, MSG);
		System.out.println("[+]testEncrypt Passed");
	}

	public static void main(String[] args){
		
		testEncryptDecrypt();

	}
}
