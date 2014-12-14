package net.mikeski.lib.encryption;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

/**
 * @author JavaDigest
 * 
 */
public class EncryptionUtil {
	private String privateKeyFile;
	private String publicKeyFile;

	private PublicKey publicKey;
	private PrivateKey privateKey;

	/**
	 * String to hold name of the encryption algorithm.
	 */
	//public static final String ALGORITHM = "RSA";
	public static final String ALGORITHM = "RSA";
	/**
	 * @param privKeyFile
	 *            File containing the serialized private key
	 * @param pubKeyFile
	 *            File containing the serialized public key
	 * @throws EncryptionUtilException
	 */
	public EncryptionUtil(String privKeyFile, String pubKeyFile,
			boolean createIfNeeded) throws EncryptionUtilException {
		publicKeyFile = pubKeyFile;
		privateKeyFile = privKeyFile;
		try {
			loadPublicKey();
			loadPrivateKey();
		} catch (EncryptionUtilException e) {
			if (!createIfNeeded) {
				throw e;
			}
			generateKeyPair();
		}
	}

	/**
	 * @param privKeyFile
	 *            File containing the serialized private key
	 * @param pubKeyFile
	 *            File containing the serialized public key
	 * @throws IOException
	 */
	public EncryptionUtil(String keyFile, KeyType keyType)
			throws EncryptionUtilException, IOException {

		switch (keyType) {
		case PRIVATE:
			privateKeyFile = keyFile;
			loadPrivateKey();
			break;
		case PUBLIC:
			publicKeyFile = keyFile;
			loadPublicKey();
			break;
		default:
			throw new EncryptionUtilException("Cannot determine if key ["
					+ keyType + "] is EncryptionUtil.PUB or EncryptionUtil.PRI");
		}
	}

	protected ObjectInputStream getInputStreamForFile(String file)
			throws FileNotFoundException, IOException {
		return new ObjectInputStream(new FileInputStream(file));
	}

	protected void loadPrivateKey() throws EncryptionUtilException {
		ObjectInputStream inputStream = null;
		PrivateKey pk = null;

		// Encrypt the string using the public key
		try {
			inputStream = getInputStreamForFile(privateKeyFile);
			pk = (PrivateKey) inputStream.readObject();
		} catch (ClassNotFoundException e) {
			throw new EncryptionUtilException("Class PrivateKey not found: "
					+ privateKeyFile, e);
		} catch (FileNotFoundException e) {
			throw new EncryptionUtilException(
					"File for private key not found: " + privateKeyFile, e);
		} catch (IOException e) {
			throw new EncryptionUtilException("IOException for private key: "
					+ privateKeyFile, e);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		privateKey = pk;
	}

	protected void loadPublicKey() throws EncryptionUtilException {
		ObjectInputStream inputStream = null;
		PublicKey pk = null;

		// Encrypt the string using the public key
		try {
			inputStream = getInputStreamForFile(publicKeyFile);
			pk = (PublicKey) inputStream.readObject();
			publicKey = pk;
		} catch (FileNotFoundException e) {
			throw new EncryptionUtilException("Cannot find file: "
					+ publicKeyFile, e);
		} catch (IOException e) {
			throw new EncryptionUtilException("IO Error reading: "
					+ publicKeyFile, e);
		} catch (ClassNotFoundException e) {
			throw new EncryptionUtilException("Class PublicKey not found: "
					+ publicKeyFile, e);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public byte[] encrypt(String text) throws EncryptionUtilException {
		byte[] cipherText = null;
		if (publicKey == null) {
			throw new EncryptionUtilException("Public key is null in encrypt");
		}
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			cipherText = cipher.doFinal(text.getBytes());

		} catch (Exception e) {
			throw new EncryptionUtilException("Exception encrypting string", e);
		}
		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws EncryptionUtilException
	 * @throws java.lang.Exception
	 */
	public String decrypt(byte[] text) throws EncryptionUtilException {
		byte[] dectyptedText = null;
		if (text == null || text.length == 0) {
			throw new EncryptionUtilException("Private key is null in decrypt");
		}

		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			// ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	public void generateKeyPair() throws EncryptionUtilException {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(2048);
			KeyPair kp = keyGen.generateKeyPair();

			this.privateKey = kp.getPrivate();
			this.publicKey = kp.getPublic();

			ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(this.privateKeyFile));
			oos.writeObject(this.privateKey);
			oos.close();

			oos = new ObjectOutputStream(new FileOutputStream(
					this.publicKeyFile));
			oos.writeObject(this.publicKey);
			oos.close();
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionUtilException(
					"NoSuchAlgorithmException generating key pair", e);
		} catch (FileNotFoundException e) {
			throw new EncryptionUtilException(
					"FileNotFoundException generating key pair", e);
		} catch (IOException e) {
			throw new EncryptionUtilException(
					"IOException generating key pair", e);
		}
	}

	public static void main(String[] args) throws EncryptionUtilException {
		EncryptionUtil u = new EncryptionUtil("/home/mike/.ssh/Jid_rsa",
				"/home/mike/.ssh/Jid_rsa.pub", true);
		byte[] encrypted = u.encrypt("asdf");
		System.out.println(encrypted);
		System.out.println(u.decrypt(encrypted));
	}
}
