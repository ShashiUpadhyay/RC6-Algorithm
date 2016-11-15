
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;

public class RC6 {

	static int w = 32, r = 20;
	static int _2RPLUS2 = 2 * r + 2;
	static int _2RPLUS3 = 2 * r + 3;
	static int _2RPLUS4 = 2 * r + 4;
	static int WBY8 = w / 8;
	static String replaceHEXDOTS = "$0 ";
	static int AUX, t, u, A, B, C, D;
	static int Pw = 0xb7e15163, Qw = 0x9e3779b9, lgw = 5;
	static int HEX_255 = 0xff;

	static int[] key_schedule;
	static String input_file_name, output_file_name;

	public int[] KeySchedule(byte[] key) {

		int[] S = new int[_2RPLUS4];
		S[0] = Pw;

		int c = key.length / (WBY8);
		int[] L = bytesToStringConversion(key, c);

		for (int i = 1; i <= (_2RPLUS3); i++) {
			S[i] = S[i - 1] + Qw;
		}

		int i, j;

		A = B = i = j = 0;

		int v = 3 * Math.max(c, (_2RPLUS4));

		for (int s = 0; s < v; s++) {
			A = S[i] = ROTL((S[i] + A + B), 3);
			B = L[j] = ROTL(L[j] + A + B, A + B);
			i = (i + 1) % (2 * r + 4);
			j = (j + 1) % c;
		}

		return S;
	}

	public byte[] encryption(byte[] keySchArray) {

		int[] encrypt_register = new int[keySchArray.length / 4];

		Arrays.fill(encrypt_register, 0);

		encrypt_register = convertBytetoInt(keySchArray, encrypt_register.length);

		A = B = C = D = t = u = 0;
		A = encrypt_register[0];
		B = encrypt_register[1];
		C = encrypt_register[2];
		D = encrypt_register[3];

		B = B + key_schedule[0];
		D = D + key_schedule[1];

		byte[] Final_Ciphertxt = new byte[keySchArray.length];
		for (int i = 1; i <= r; i++) {

			t = ROTL(B * (2 * B + 1), lgw);
			u = ROTL(D * (2 * D + 1), lgw);
			A = ROTL(A ^ t, u) + key_schedule[2 * i];
			C = ROTL(C ^ u, t) + key_schedule[2 * i + 1];

			AUX = A;
			A = B;
			B = C;
			C = D;
			D = AUX;
		}

		A = A + key_schedule[_2RPLUS2];
		C = C + key_schedule[_2RPLUS3];

		encrypt_register[0] = A;
		encrypt_register[1] = B;
		encrypt_register[2] = C;
		encrypt_register[3] = D;

		Final_Ciphertxt = convertIntToByte(encrypt_register, keySchArray.length);

		return Final_Ciphertxt;
	}

	public byte[] decryption(byte[] ciphertxtval) {

		A = B = C = D = t = u = 0;
		int[] decryt_register = new int[ciphertxtval.length / 4];

		Arrays.fill(decryt_register, 0);

		decryt_register = convertBytetoInt(ciphertxtval, decryt_register.length);

		A = decryt_register[0];
		B = decryt_register[1];
		C = decryt_register[2];
		D = decryt_register[3];

		C = C - key_schedule[_2RPLUS3];
		A = A - key_schedule[_2RPLUS2];

		byte[] Final_Ciphertxt = new byte[ciphertxtval.length];
		for (int i = r; i >= 1; i--) {
			AUX = D;
			D = C;
			C = B;
			B = A;
			A = AUX;

			u = ROTL(D * (2 * D + 1), lgw);
			t = ROTL(B * (2 * B + 1), lgw);
			C = ROTR(C - key_schedule[2 * i + 1], t) ^ u;
			A = ROTR(A - key_schedule[2 * i], u) ^ t;

		}
		D = D - key_schedule[1];
		B = B - key_schedule[0];

		decryt_register[0] = A;
		decryt_register[1] = B;
		decryt_register[2] = C;
		decryt_register[3] = D;

		Final_Ciphertxt = convertIntToByte(decryt_register, ciphertxtval.length);

		return Final_Ciphertxt;
	}

	private static int ROTL(int val, int pas) {
		return (val << pas) | (val >>> (32 - pas));
	}

	private static int ROTR(int val, int pas) {
		return (val >>> pas) | (val << (32 - pas));
	}

	public static byte[] convertIntToByte(int[] integerArray, int length) {
		byte[] int_to_byte = new byte[length];
		for (int i = 0; i < length; i++) {
			int_to_byte[i] = (byte) ((integerArray[i / 4] >>> (i % 4) * 8) & HEX_255);
		}
		return int_to_byte;
	}

	private static int[] convertBytetoInt(byte[] arr, int length) {
		int[] byte_to_int = new int[length];
		Arrays.fill(byte_to_int, 0);
		int counter = 0;
		for (int i = 0; i < byte_to_int.length; i++) {
			byte_to_int[i] = ((arr[counter++] & HEX_255)) | ((arr[counter++] & HEX_255) << 8)
					| ((arr[counter++] & HEX_255) << 16) | ((arr[counter++] & HEX_255) << 24);
		}
		return byte_to_int;
	}

	private static int[] bytesToStringConversion(byte[] userkey, int c) {
		int[] bytes_to_string = new int[c];
		Arrays.fill(bytes_to_string, 0);
		for (int i = 0, off = 0; i < c; i++)
			bytes_to_string[i] = ((userkey[off++] & HEX_255)) | ((userkey[off++] & HEX_255) << 8)
					| ((userkey[off++] & HEX_255) << 16) | ((userkey[off++] & HEX_255) << 24);
		return bytes_to_string;
	}

	// referred from
	// http://www.java-examples.com/convert-java-string-byte-example
	public static byte[] stringToByteArray(String s) {
		int input_string_length = s.length();
		byte[] data = new byte[input_string_length / 2];
		for (int i = 0; i < input_string_length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	// referred
	// https://www.mkyong.com/java/how-do-convert-byte-array-to-string-in-java/
	public static String byteArrayToString(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x", b & HEX_255));
		return sb.toString();
	}

	public static void main(String[] args) {
		String plain_text, decrypted_text, key_value, cipher_text_to_decrypt, key_value_for_decryption;
		BufferedReader bf_reader = null;
		BufferedWriter bf_writer = null;

//		input_file_name = "input_d.txt";
//		output_file_name = "output_d.txt";
		
		if (args.length == 2) {
			if (args[0] != null) {
				input_file_name = args[0];
			}
			if (args[1] != null) {
				output_file_name = args[1];
			}

			try {
				File input_file  = new File(input_file_name);
				File output_file = new File(output_file_name);
				if(output_file != null){
					if(!output_file.exists()){
						output_file.createNewFile();
					}
				}
				
				bf_reader = new BufferedReader(new FileReader(input_file));
				String operation = bf_reader.readLine();

				if (operation != null) {
					if (operation.equalsIgnoreCase("Encryption")) {

						if ((plain_text = bf_reader.readLine()) != null) {
							plain_text = plain_text.split(":")[1];
						}
						if ((key_value = bf_reader.readLine()) != null) {
							key_value = key_value.split(":")[1];
						}

						byte[] key_in_byte = stringToByteArray(key_value.replaceAll("\\s", "").trim());
						key_schedule = new RC6().KeySchedule(key_in_byte);
						
						byte[] plaintext_in_byte = stringToByteArray(plain_text.replaceAll("\\s", "").trim());
						byte[] encrypt = new RC6().encryption(plaintext_in_byte);
						
						String encrypted_text = byteArrayToString(encrypt);
						encrypted_text = encrypted_text.replaceAll("..", replaceHEXDOTS);

						bf_writer = new BufferedWriter(new FileWriter(output_file.getAbsolutePath()));
						bf_writer.write("ciphertext: " + encrypted_text);
//						System.out.println("ciphertext: " + encrypted_text);

					} else if (operation.equalsIgnoreCase("Decryption")) {

						if ((cipher_text_to_decrypt = bf_reader.readLine()) != null) {
							cipher_text_to_decrypt = cipher_text_to_decrypt.split(":")[1];
						}
						if ((key_value_for_decryption = bf_reader.readLine()) != null) {
							key_value_for_decryption = key_value_for_decryption.split(":")[1];
						}

						byte[] key_decrypt_byte = stringToByteArray(
								key_value_for_decryption.replaceAll("\\s", "").trim());
						byte[] cipher_text_byte = stringToByteArray(
								cipher_text_to_decrypt.replaceAll("\\s", "").trim());

						key_schedule = new RC6().KeySchedule(key_decrypt_byte);

						byte[] decrypt_text_byte = new RC6().decryption(cipher_text_byte);

						String decryption_output = byteArrayToString(decrypt_text_byte);
						decrypted_text = decryption_output.replaceAll("..", replaceHEXDOTS);

						bf_writer = new BufferedWriter(new FileWriter(output_file));
						bf_writer.write("plaintext: " + decrypted_text);
//						System.out.println("plaintext: " + decrypted_text);
					}
					bf_writer.close();

				}

			} catch (FileNotFoundException e) {
				System.out.println("File not found exception");
				e.printStackTrace();
			} catch (IOException e) {
				System.out.println("IO exception");
				e.printStackTrace();
			} finally {

			}
		}else{
			System.out.println("Two input arguments are required.");
			System.out.println("java <compile_java_file> <Input_file_name> <Output_file_name>");
		}
	}
}