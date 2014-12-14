package net.mikeski.lib.encryption;

/**
 * Exception in the encryption lib.
 * 
 * @author mike
 *
 */
public class EncryptionUtilException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4963157816522709017L;

	public EncryptionUtilException(String message) {
		super(message);
	}

	public EncryptionUtilException(String message, Exception e) {
		super(message, e);
	}
}
