/**
 * 
 */
package net.mikeski.test.lib.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

import net.mikeski.lib.encryption.EncryptionUtil;
import net.mikeski.lib.encryption.EncryptionUtilException;

import org.junit.Test;

import junit.framework.TestCase;

/**
 * @author mike
 *
 */
public class TestEncryptionUtil extends TestCase {	
	private String pubFile = "/tmp/pub.rsa";
	private String priFile = "/tmp/pri.rsa";
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
		delete(pubFile);
		delete(priFile);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
		delete(pubFile);
		delete(priFile);
	}
	
	private void delete(String fileName){
		File f = new File(fileName);
		if(f != null){
			f.delete();
		}
	}
	
	@Test
	public void testCreateKeysAndUseExisting() throws EncryptionUtilException, IOException{
		assertFalse(new File(priFile).exists());

		EncryptionUtil eu = new EncryptionUtil(priFile, pubFile, true);
		assertNotNull("Cannot create EncryptionUtil", eu);
		
		String str = "This will be encrypted";
		String str2 = "This will not be the same";
		
		byte[] enc = eu.encrypt(str);
		assertNotNull("Encrypted data is null: " + str, enc);
		assertTrue(str.equals(eu.decrypt(enc)));
		assertTrue(new File(priFile).exists());

		// Read the file, create a new object to make
		// sure that the keys are re-used since they exist
		FileInputStream fis = new FileInputStream(priFile);
		byte[] priKeyFileContents = new byte[fis.available()];
		fis.read(priKeyFileContents);
		fis.close();
		
		eu = new EncryptionUtil(priFile, pubFile, true);
		byte[] enc2 = eu.encrypt(str2);
		assertNotNull("Encrypted data is null: " + str2, enc2);
		assertTrue(str2.equals(eu.decrypt(enc2)));
		assertTrue(new File(priFile).exists());
		
		fis = new FileInputStream(priFile);
		byte[] priKeyFileContents2 = new byte[fis.available()];
		fis.read(priKeyFileContents2);
		fis.close();
		
		assertTrue(Arrays.equals(priKeyFileContents, priKeyFileContents2));
	}
	
}
