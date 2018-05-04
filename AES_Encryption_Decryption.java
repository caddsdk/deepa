import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;

public class AES_Encryption_Decryption {
	/* We need the Thid Party Jar file commons-codec-1.7.jar */
	private static final String ALGO = "AES";
	public static String encrypt(String Data, String keyWord) throws Exception {

		keyWord = keyWord.substring(0, 16);
		byte[] keyValue = keyWord.getBytes();
		System.out.println("Size : " + keyValue.length);/*string converted into bytes*/
		Key key = new SecretKeySpec(keyValue, ALGO);/*produces key using whatever key value is given of type byte and algorithm AES*/ 
		Cipher c = Cipher.getInstance(ALGO);/*get cipher text of type algo by getting instance of aes algo*/
		c.init(Cipher.ENCRYPT_MODE, key);/*initialise cipher to encrypt mode with key*/
		String encryptedValue = new String(Base64.encode(Data.getBytes()));//data is encode .convert to string 
		return encryptedValue;
	}
	public static String decrypt(String encryptedData, String keyWord)
			throws Exception {

		keyWord = keyWord.substring(0, 16);
		byte[] keyValue = keyWord.getBytes();/*string converted into bytes*/
		Key key = new SecretKeySpec(keyValue, ALGO);/*produces key using whatever key value is given of type byte and algorithm AES*/ 
		Cipher c = Cipher.getInstance(ALGO);/*get cipher text of type algo by getting instance of aes algo*/
		c.init(Cipher.DECRYPT_MODE, key);/*initialise cipher to decrypt mode with key*/
		String decryptedValue = new String(Base64.decode(encryptedData
				.getBytes()));/*decrpyt data n covert to string*/
		return decryptedValue;
	}
	public static void main(String[] args) {
		String password = "mypassword";

		String keyWord = "ef50a0ef2c3e3a5fdf803ae9752c8c66";

		try {
			String passwordEnc = AES_Encryption_Decryption.encrypt(password,
					keyWord);
			String passwordDec = AES_Encryption_Decryption.decrypt(
					passwordEnc, keyWord);
			System.out.println("Plain Text : " + password);
			System.out.println("Encrypted Text : " + passwordEnc);
			System.out.println("Decrypted Text : " + passwordDec);

		} catch (Exception e) {
			System.out.println("Opps,Exception In AES_EncrypterNdecrypter=>main() :");
			e.printStackTrace();
		}

	}

}

