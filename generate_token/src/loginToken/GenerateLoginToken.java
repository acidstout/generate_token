/*******************************************************************************
 * 
 * loginToken application
 * Version 1.0
 * 
 * @author Nils Rekow
 * @created 2016-01-19
 * 
 * Generates tokens from supplied command line arguments for single sign-on purposes.
 * Tokens contain some user ID and the timestamp of generation, and are AES-128 encrypted.
 * The result is Base64- and URL-encoded.
 * 
 * Supports PBKDF2 hashing and hexadecimal secret key. Both optional.
 * 
 * Usage:
 * ------
 * 		First compile the code.
 * 
 *			javac GenerateLoginToken.java
 * 
 * 		Then supply a list of usernames and/or their respective GUIDs concatenated by an equality sign,
 *     		and separated by a space via command-line parameter:
 * 
 * 			java GenerateLoginToken username1={12345678-9012-AB34-CDEF-567890123456} username2={09876543-2109-FE87-DCBA-654321098765} ...
 * 
 * 		You need to supply at least one single string as parameter. No matter if it's a username, a GUID or both
 * 		separated by an equality sign. So, something like this is totally valid, too:
 * 
 *  		java GenerateLoginToken username1 username2 ...
 *  
 *  Result:
 *  -------
 *  	The result will be something like this:
 *  
 *  		blah = https://example.com/app?token=6icAtIasSM99R0kWq7er8g%3D%3D%3AoCYqMl5j%2F7oYYeYf4GukzrrwGcYHWjXhHTX63oPsTj37YPeRg2B%2Bxo7SlAMhyjn3
 * 
 ******************************************************************************/
package loginToken;

//Imports
import java.io.UnsupportedEncodingException;	// Used by getBytes() in generateKey()
import java.net.URLEncoder;						// Urlencode the login token.
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;				// SHA-256
import java.security.NoSuchAlgorithmException;	// SHA-256
import java.security.SecureRandom;				// Generate random IV.
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;				// Format timestamp of login token generation.
import java.util.Arrays;
import java.util.Base64;						// Requires JDK 8.
import java.util.Calendar;						// Get current date/time.
import java.util.Date;							// Get current date/time.
import java.util.Iterator;						// Iterate through the TreeMap of GUIDs.
import java.util.Map.Entry;						// Get each entry of the TreeMap.
import java.util.TimeZone;						// Get current date/time. We use UTC.
import java.util.TreeMap;						// Holds sorted list of GUIDs.

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;						// AES
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;					// AES
import javax.crypto.spec.IvParameterSpec;		// AES
import javax.crypto.spec.SecretKeySpec;			// AES
import javax.crypto.spec.PBEKeySpec;			// AES. Only required when using PBKDF2 salted password hashing.
import javax.crypto.SecretKeyFactory;			// AES. Only required when using PBKDF2 salted password hashing.

import javax.xml.bind.DatatypeConverter;		// Used to convert hex string into byte[].


public class GenerateLoginToken {
	// Hard-coded configuration.
	// TODO: Make this configurable via command line.
	private static final boolean use_simple_AES   = false;								// If set to true, we don't use PBKDF2 salted password hashing.

	private static final int keysize              = 128;								// 128 bits keysize. Alternatively use 192 or 256 bits.
	private static final int iterations           = 65535;								// Number of iterations. Higher is better, but also slower.
	
	private static final String defaultCharset    = "UTF-8";							// Default charset.
	private static final String defaultTimezone   = "UTC";								// Default timezone.
	private static final String defaultTimeformat = "yyyyMMddHHmmss";					// Format of timestamp in payload.
	private static final String algorithm         = "AES";								// Base algorithm type is "AES".
	private static final String transformation    = "AES/CBC/PKCS5Padding";				// The actual name of the transformation.
	
	private static String encryptionKey           = "Secret";							// Demo encryption key. Proper one will be set in configuration.
	private static String url                     = "https://example.com/app?token=";	// Demo URL where the application runs.
	
	/**
	 * Check if a string is a hexadecimal value 
	 * @param str
	 * @return
	 */
	private static boolean isHex(final String str) {
		return str.matches("[0-9a-fA-F]+") && str.length() % 2 == 0;
	}
	
	
	/**
	 * Use a string to generate a valid byte array from, which complies to the defined keysize.
	 *
	 * @param str
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] generateKey(final String str) throws UnsupportedEncodingException, NoSuchAlgorithmException { 
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		byte[] key = sha.digest(str.getBytes(defaultCharset));
		return Arrays.copyOf(key, (keysize / 8));
	}
	
	
	/**
	 * Method to encrypt a given payload
	 * 
	 * @param payload
	 * @param iv
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 */
	private static String generatePayload(final String payload, final byte[] iv)
		throws UnsupportedEncodingException,
			NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			IllegalBlockSizeException,
			BadPaddingException,
			InvalidKeySpecException {
		
		byte[] keyBytes;
		final byte[] encValue;
		final byte[] input = payload.getBytes(defaultCharset);							// Convert payload (String) into byte[].
		final Cipher c = Cipher.getInstance(transformation);							// Set encryption algorithm.

		if (isHex(encryptionKey)) {
			try {
				keyBytes = DatatypeConverter.parseHexBinary(encryptionKey);				// Parse encryption key as hex.
			} catch (IllegalArgumentException e) {
				keyBytes = generateKey(encryptionKey);									// Generate a valid key from the given string.
			}
		} else {
			keyBytes = generateKey(encryptionKey);										// Generate a valid key from the given string.
		}

		if (use_simple_AES) {
			final SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);			// Prepare secret key.
			c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));			// Prepare encryption.
		} else {
			String encryptionKey_tmp = new String(keyBytes, defaultCharset);			// Convert byte[] into String ...
			final PBEKeySpec spec = new PBEKeySpec(encryptionKey_tmp.toCharArray(), iv, iterations, keysize);	// ... convert String to char[] in order to use it with PBEKeySpec.
			final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");	// Use PBKDF2 salted password hashing.
			final SecretKey secretKey = factory.generateSecret(spec);					// Prepare secret key.
			final SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), algorithm);
			c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));				// Prepare encryption.
		}

		encValue = c.doFinal(input);													// Encrypt payload.
		return Base64.getEncoder().encodeToString(encValue);							// Base64 encode encrypted payload.
	}
	
	
	/**
	 * Returns current date and time of now as string.
	 * 
	 * @return String
	 */
	private static String getCalenderNow() {
		final Calendar cal = Calendar.getInstance();									// New calendar object.
		final SimpleDateFormat formatter = new SimpleDateFormat(defaultTimeformat);		// Set date/time format.
		formatter.setTimeZone(TimeZone.getTimeZone(defaultTimezone));					// Set timezone to UTC.
		cal.setTime(new Date());														// Set calendar object to "now".
		return formatter.format(cal.getTime());
	}
	
	
	/**
	 * Main routine
	 * 
	 * @param args
	 */
	public static void main(final String[] args) {
		// Prepare a TreeMap with the string(s) supplied on command line.
		final TreeMap<String, String> userIDs = new TreeMap<String, String>();			// Create a new TreeMap. These are sorted automatically.
		userIDs.clear();																// Just in case clear our TreeMap.

		if (args.length > 0) {
			for (String s : args) {
				if (s != null && s.length() > 0 && !userIDs.containsKey(s)) {
					userIDs.put(s, null); // We just need the key.
				}
			}
		}

		// Check if our list contains at least one usable entry.
		if (!userIDs.isEmpty()) {
			final SecureRandom random = new SecureRandom();								// Init random numbers generator.
			final byte[] iv = new byte[0x10];											// 16 bytes long IV. Will be filled later.
	
			final Iterator<Entry<String, String>> it = userIDs.entrySet().iterator();	// Create Iterator object in order to iterate through our TreeMap.
			
			// Iterate through our TreeMap.
			while (it.hasNext()) {
				Entry<String, String> pair = (Entry<String, String>)it.next();
			
				if (pair.getValue() == null || pair.getValue().length() < 1) {
					System.out.println();												// Draw an empty line if the value is empty.
				} else {
					random.nextBytes(iv);												// Generate random IV.
					final String encoded_IV = Base64.getEncoder().encodeToString(iv);	// Base64 encode the IV in order to be able to generate a valid link.
					final String encryptedPayload;										// Prepare result variable.
					final String user = pair.getKey();									// We just use the key, because the value is always null.
					final String now = getCalenderNow();								// Get formatted date string
					final String payload = "{\"user\":\"" + user + "\",\"time\":\"" + now + "\"}";			// Prepare payload. Build JSON the hard way. Sufficient here.
					
					// Generate key from encryptionKey and IV, AES-encrypt payload and encode the result as Base64.
					try {
						// Encrypt payload
						encryptedPayload = generatePayload(payload, iv);

						// Build and show link to user.
						// System.out.println(encoded_IV + ":" + encryptedPayload);
						System.out.println(user + " = " + url + URLEncoder.encode(encoded_IV + ":" + encryptedPayload, defaultCharset));
					} catch (Exception e) {
						System.out.println("Could not encrypt payload: " + e);
					}
				}
				
				it.remove(); // Remove current entry from list in order to avoid a "ConcurrentModificationException".
			}
		} else {
			System.out.println("Missing parameter.");
		}
	}
}