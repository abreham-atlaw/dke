package dke.lib.security.symmetric;

import java.util.Arrays;
import java.util.Collections;

import dke.lib.utils.Logging;
import dke.lib.utils.ByteOps;


public class AES extends SymmetricEncryption{

	private final SBox sBox;
	private final StateTransformation[] transformations;

	public AES(byte[] key, boolean verbose){
		super(key, 16);

		this.sBox = onSBoxInit();
		byte[][][] roundKeys = new KeyScheduler(sBox).schedule(key);
		this.transformations = generateTransformations(roundKeys, verbose);

	}

	public AES(byte[] key){
		this(key, false);
	}

	protected AES.SBox onSBoxInit(){
		return new AES.SBox();
	}

	private StateTransformation[] generateTransformations(byte[][][] roundKeys, boolean verbose){

		StateTransformation[] transformations = new StateTransformation[4*(roundKeys.length-1)];
		transformations[0] = new AddRoundKeyTransformation(roundKeys[0], verbose);
		for(int i=0; i<roundKeys.length-1; i++){
			transformations[(4*i)+1] = new SubByteTransformation(sBox, verbose);
			transformations[(4*i)+2] = new ShiftRowsTransformation(verbose);
			if(i == roundKeys.length - 2) {
				transformations[(4 * i) + 3] = new AddRoundKeyTransformation(roundKeys[i+1], verbose);
				break;
			}
			transformations[(4*i)+3] = new MixColumnsTransformation(verbose);
			transformations[(4*i)+4] = new AddRoundKeyTransformation(roundKeys[i+1], verbose);
		}
		return transformations;

	}

	protected byte[] encryptBlock(byte[] block){
		byte[][] state = StateOps.toState(block);
		state = StateTransformation.applyTransformations(transformations, state, false);
		return StateOps.toBlock(state);
	}	
	
	protected byte[] decryptBlock(byte[] block){
		byte[][] state = StateOps.toState(block);
		state = StateTransformation.applyTransformations(transformations, state, true);
		return StateOps.toBlock(state);
	}

	public static class SBox{

		private final byte[][] sBox = new byte[16][16];
		private final byte[][] inverseSBox = new byte[16][16];

		public SBox(){
			this.initialize(sBox, inverseSBox);
		}

		public byte getValue(int row, int column){
			return sBox[row][column];
		}

		public byte getInverseValue(int row, int column){
			return inverseSBox[row][column];
		}

		protected void initialize(byte[][] sBox, byte[][] inverseSBox){
			
			int[][] sBoxValues = new int[][]{{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
			
			int[][] inverseSBoxValues = new int[][]{{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }};

			for(int i=0; i<16; i++){
				for(int j=0; j<16; j++){
					sBox[i][j] = (byte)sBoxValues[i][j];
					inverseSBox[i][j] = (byte)inverseSBoxValues[i][j];
				}
			}
		
		}
	}

	private abstract static class StateTransformation{

		private final boolean verbose;

		public StateTransformation(boolean verbose){
			this.verbose = verbose;
		}

		public StateTransformation(){
			this(false);
		}

		protected abstract byte[][] forward(byte[][] state);

		protected abstract byte[][] inverse(byte[][] state);

		protected abstract String getName();

		private String formatState(byte[][] state){
			StringBuilder builder = new StringBuilder();
			for(byte[] row: state){
				builder.append(Logging.formatByteArray(row)).append("\n");
			}
			return builder.toString();
		}

		public byte[][] apply(byte[][] state, boolean inverse){
			byte[][] newState;
			if(inverse)
				newState = inverse(state);
			else
				newState = forward(state);
			if(verbose){
				System.out.printf("\n\nTransformation: %s\nInverse: %b\n\nInitial State:\n%s\nFinal State:\n%s\n\n", getName(), inverse, formatState(state), formatState(newState));
			}
			return newState;
		}

		public static byte[][] applyTransformations(StateTransformation[] transformations, byte[][] state, boolean inverse){
			byte[][] newState = state;

			StateTransformation[] orderedTransformations = Arrays.copyOf(transformations, transformations.length);
			if(inverse)
				Collections.reverse(Arrays.asList(orderedTransformations));
			for(StateTransformation transformation: orderedTransformations){
				newState = transformation.apply(newState, inverse);
			}
			return newState;
		}

	}

	private static class SubByteTransformation extends StateTransformation{

		private SBox sBox;

		public SubByteTransformation(SBox sBox, boolean verbose){
			super(verbose);
			init(sBox);
		}

		public SubByteTransformation(SBox sBox){
			super();
			init(sBox);
		}

		private void init(SBox sBox){
			this.sBox = sBox;
		}

		private int[] getRowColumn(byte value){
			int unsignedValue = Byte.toUnsignedInt(value);
			int row = unsignedValue >> 4;
			int column = unsignedValue & 15;
			return new int[]{row, column};
		}

		private byte[][] transform(byte[][] state, boolean inverse){
			byte[][] newState = new byte[state.length][state[0].length];
			for(int i=0; i<state.length; i++){
				for(int j=0; j<state[0].length; j++){
					int[] rowColumn = getRowColumn(state[i][j]);
					if(inverse)
						newState[i][j] = sBox.getInverseValue(rowColumn[0], rowColumn[1]);
					else
						newState[i][j] = sBox.getValue(rowColumn[0], rowColumn[1]);
				}
			}
			return newState;
		}

		@Override
		protected byte[][] forward(byte[][] state) {
			return transform(state, false);
		}

		@Override
		protected byte[][] inverse(byte[][] state) {
			return transform(state, true);
		}

		@Override
		protected String getName() {
			return "SubByte";
		}
	}

	private static class AddRoundKeyTransformation extends StateTransformation{

		private byte[][] key;

		public AddRoundKeyTransformation(byte[][] key, boolean verbose){
			super(verbose);
			init(key);
		}

		public AddRoundKeyTransformation(byte[][] key){
			super();
			init(key);
		}

		private void init(byte[][] key){
			this.key = key;
		}

		private byte[][] transform(byte[][] state){
			return StateOps.toState(ByteOps.xor(StateOps.toBlock(state), StateOps.toBlock(key)));
		}

		@Override
		protected byte[][] forward(byte[][] state) {
			return transform(state);
		}

		@Override
		protected byte[][] inverse(byte[][] state) {
			return transform(state);
		}

		@Override
		protected String getName() {
			return "AddRoundKey";
		}
	}

	private static class ShiftRowsTransformation extends StateTransformation{

		public ShiftRowsTransformation(){
			super();
		}

		public ShiftRowsTransformation(boolean verbose){
			super(verbose);
		}

		private byte[][] transform(byte[][] state, boolean inverse){
			byte[][] newState = new byte[state.length][state[0].length];

			int direction = 1;
			if(inverse)
				direction = -1;

			for(int i=0; i<state.length; i++){

				for(int j=0; j<state[0].length; j++){

					newState[i][j] = state[i][(2*state[i].length + j + direction*i)%state[i].length];

				}

			}

			return newState;

		}

		@Override
		protected byte[][] forward(byte[][] state) {
			return transform(state, false);
		}

		@Override
		protected byte[][] inverse(byte[][] state) {
			return transform(state, true);
		}

		@Override
		protected String getName() {
			return "ShiftRows";
		}
	}

	private static class MixColumnsTransformation extends StateTransformation{

		public MixColumnsTransformation(boolean verbose){
			super(verbose);
		}

		private static final byte[][] FORWARD_MATRIX = new byte[][]{
				{2, 3, 1, 1},
				{1, 2, 3, 1},
				{1, 1, 2, 3},
				{3, 1, 1, 2}
		};

		private static final byte[][] INVERSE_MATRIX = new byte[][]{
				{14, 11, 13, 9},
				{9, 14, 11, 13},
				{13, 9, 14, 11},
				{11, 13, 9, 14}
		};

		private byte[][] transform(byte[][] state, byte[][] mtx){
			byte[][] newState = new byte[state.length][state[0].length];
			for(int i=0; i<newState[0].length; i++){
				ByteOps.setColumn(
						newState,
						ByteOps.reshape(
								ByteOps.GaloisField.matMul(
									mtx,
									ByteOps.reshape(new byte[][]{ByteOps.getColumn(state, i)}, newState.length, 1)
								),
								1,
								newState.length
						)[0],
						i
				);
			}
			return newState;
		}
		
		@Override
		protected byte[][] forward(byte[][] state) {
			return transform(state, FORWARD_MATRIX);
		}

		@Override
		protected byte[][] inverse(byte[][] state) {
			return transform(state, INVERSE_MATRIX);
		}

		@Override
		protected String getName() {
			return "MixColumn";
		}
	}

	private static class KeyScheduler{

		private final SubByteTransformation subWord;
		private final ShiftRowsTransformation rotWord = new ShiftRowsTransformation();
		public KeyScheduler(SBox sBox){
			subWord = new SubByteTransformation(sBox);
		}

		private byte[][] toState(byte[] word){
			return new byte[][]{word};
		}

		private byte[] toWord(byte[][] state){
			return state[0];
		}

		public byte[][][] schedule(byte[] key){
			int rounds = 10;
			byte[][][] roundKeys = new byte[rounds+1][4][4];
			roundKeys[0] = StateOps.toState(key);
			byte[] lastword;

			for(int i=1; i<roundKeys.length; i++){
				byte[] rCon = new byte[]{(byte)Math.pow(2, i-1), 0, 0, 0};
				lastword = ByteOps.xor(
						toWord(
								subWord.apply(
										rotWord.apply(
												toState(
														ByteOps.getColumn(roundKeys[i-1], 3)
												),
												false
										),
										false
								)
						),
						rCon
				);
				for(int j=0; j<4; j++){
					ByteOps.setColumn(
							roundKeys[i],
							ByteOps.xor(lastword, ByteOps.getColumn(roundKeys[i-1], j)),
							j
					);
					lastword = ByteOps.getColumn(roundKeys[i], j);
				}
			}
			return roundKeys;
		}

	}

	private static class StateOps{

		private static byte[][] toState(byte[] block){
			byte[][] state = new byte[4][4];
			for(int i=0; i<4; i++){
				for(int j=0; j<4; j++){
					state[j][i] = block[(i*4)+j];
				}
			}
			return state;
		}

		private static byte[] toBlock(byte[][] state){
			byte[] block = new byte[16];
			for(int i=0; i<4; i++){
				for(int j=0; j<4; j++){
					block[(i*4)+j] = state[j][i];
				}
			}
			return block;
		}

	}

}
