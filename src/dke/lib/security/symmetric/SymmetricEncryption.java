package dke.lib.security.symmetric;


import java.util.Arrays;


public abstract class SymmetricEncryption{

	protected byte[] key;
	private final int blockSize;

	public SymmetricEncryption(byte[] key, int blockSize){ // BLOCK SIZE IN BYTES
		this.key = key;
		this.blockSize = blockSize;
	}

	abstract protected byte[] encryptBlock(byte[] block);

	abstract protected byte[] decryptBlock(byte[] block);

	private byte[] addPadding(byte[] msg, int blockSize){ //CMS SCHEME IS DEFAULT
		int paddingSize = blockSize - (msg.length % blockSize);
		byte[] paddedMessage = new byte[msg.length + paddingSize];
		System.arraycopy(msg, 0, paddedMessage, 0, msg.length);
		for(int i=msg.length; i<paddedMessage.length; i++){
			paddedMessage[i] = (byte)paddingSize;
		}
		return paddedMessage;
	}

	private byte[] removePadding(byte[] msg, int blockSize){
		int paddingSize = msg[msg.length - 1];
		return Arrays.copyOfRange(msg, 0, msg.length - paddingSize);
	}

	public byte[][] toBlocks(byte[] msg){
		int numBlocks = msg.length/blockSize;
		byte[][] blocks = new byte[numBlocks][blockSize];
		for(int i=0; i<numBlocks; i++){
			blocks[i] = Arrays.copyOfRange(msg, i*blockSize, (i+1)*blockSize);
		}
		return blocks;
	}

	public byte[] encrypt(byte[] msg){
		byte[] paddedMsg = addPadding(msg, blockSize);
		byte[] encryptedMsg = new byte[paddedMsg.length];
		byte[][] blocks = toBlocks(paddedMsg);
		for(int i=0; i<blocks.length; i++){
			byte[] encryptedBlock = encryptBlock(blocks[i]);
			System.arraycopy(encryptedBlock, 0, encryptedMsg, i*blockSize, encryptedBlock.length);
		}
		return encryptedMsg;
	}

	public byte[] decrypt(byte[] msg){
		byte[] decryptedMsg = new byte[msg.length];
		byte[][] blocks = toBlocks(msg);
		for(int i=0; i<blocks.length; i++){
			byte[] decryptedBlock = decryptBlock(blocks[i]);
			System.arraycopy(decryptedBlock, 0, decryptedMsg, i*blockSize, decryptedBlock.length);
		}
		return removePadding(decryptedMsg, blockSize);
	}

}
