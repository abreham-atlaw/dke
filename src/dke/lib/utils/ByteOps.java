package dke.lib.utils;

import java.util.stream.IntStream;

public class ByteOps {

	public static byte[] getColumn(byte[][] matrix, int idx){
		byte[] column = new byte[matrix.length];
		IntStream.range(0, column.length).forEach(i -> column[i] = matrix[i][idx]);
		return column;
	}

	public static void setColumn(byte[][] matrix, byte[] column, int idx){
		IntStream.range(0, column.length).forEach(i -> matrix[i][idx] = column[i]);
	}

	public static byte[] xor(byte[] vector0, byte[] vector1){
		byte[] result = new byte[vector0.length];
		for(int i=0; i<result.length; i++){
			result[i] = (byte)(vector0[i] ^ vector1[i]);
		}
		return result;

	}

	public static byte[][] reshape(byte[][] matrix, int m, int n) {
		if(matrix.length*matrix[0].length != m*n){
			throw new IllegalArgumentException("New matrix must be of same area as old matrix.");
		}
		byte[][] result = new byte[m][n];
		byte[] temp = new byte[matrix.length * matrix[0].length];

		int index = 0;
		for (byte[] row : matrix) {
			for (int j = 0; j < matrix[0].length; j++) {
				temp[index++] = row[j];
			}
		}

		index = 0;
		for(int i = 0;i<n;i++){
			for(int j = 0;j<m;j++){
				result[j][i] = temp[index++];
			}

		}
		return result;
	}

	public static class GaloisField{

		public static byte mul(byte a, byte b){
			byte p = 0;

			for (int counter = 0; counter < 8; counter++) {
				if ((b & 1) != 0) {
					p ^= a;
				}

				boolean hi_bit_set = (a & 0x80) != 0;
				a <<= 1;
				if (hi_bit_set) {
					a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
				}
				b >>= 1;
			}

			return p;
		}

		public static byte sum(byte[] bytes){
			byte result = 0;
			for(byte b: bytes){
				result ^= b;
			}
			return result;
		}

		public static byte[] dot(byte[] vector0, byte[] vector1){
			byte[] result = new byte[vector0.length];
			for(int i=0; i<result.length; i++){
				result[i] = mul(vector0[i], vector1[i]);
			}
			return result;
		}

		public static byte[][] matMul(byte[][] matrix0, byte[][] matrix1){
			byte[][] result = new byte[matrix0.length][matrix1[0].length];
			for(int i=0; i<result.length; i++){
				for(int j=0; j<result[0].length; j++){
					result[i][j] = sum(dot(matrix0[i], getColumn(matrix1, j)));
				}
			}
			return result;
		}

	}

}
