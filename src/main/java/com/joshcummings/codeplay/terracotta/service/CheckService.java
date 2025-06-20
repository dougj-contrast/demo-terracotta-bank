/*
 * Copyright 2015-2018 Josh Cummings
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.joshcummings.codeplay.terracotta.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.joshcummings.codeplay.terracotta.model.Check;
import org.springframework.stereotype.Service;

/**
 * This class makes Terracotta Bank vulnerable to SQL injection
 * attacks because it concatenates queries instead of using
 * bind variables.
 *
 * This class also makes the site vulnerable to Directory
 * Traversal attacks because it concatenates user input to
 * compose file system paths.
 *
 * @author Josh Cummings
 */
@Service
public class CheckService extends ServiceSupport {
	private static final String CHECK_IMAGE_LOCATION = "images/checks";
	static {
		new File(CHECK_IMAGE_LOCATION).mkdirs();
	}
	
	public void addCheck(Check check) {
		runUpdate("INSERT INTO checks (id, number, amount, account_id)"
				+ " VALUES ('" + check.getId() + "','" + check.getNumber() + 
				"','" + check.getAmount() + "','" + check.getAccountId() + "')");
	}

	public void updateCheckImagesBulk(String checkNumber, InputStream is) {
		// Validate the base check number
		if (checkNumber == null || checkNumber.isEmpty()) {
			throw new IllegalArgumentException("Invalid check number");
		}
		
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ( (ze = zis.getNextEntry()) != null ) {
				try {
					String entryName = ze.getName();
					// Validate the entry name to prevent path traversal
					if (entryName != null && !entryName.contains("..") && !entryName.startsWith("/")) {
						updateCheckImage(checkNumber + "/" + entryName, zis);
					} else {
						throw new IllegalArgumentException("Invalid entry name in zip file");
					}
				} catch ( Exception e ) {
					e.printStackTrace(); // try to upload the other ones
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void updateCheckImage(String checkNumber, InputStream is) {
		// Validate the check number to prevent path traversal
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number");
		}
		
		try {
			File file = new File(CHECK_IMAGE_LOCATION, checkNumber);
			file.getParentFile().mkdirs(); // Create parent directories if needed
			
			try ( FileOutputStream fos = new FileOutputStream(file) ) {
				byte[] b = new byte[1024];
				int read;
				while ( ( read = is.read(b) ) != -1 ) {
					fos.write(b, 0, read);
				}
			} catch ( IOException e ) {
				throw new IllegalArgumentException(e);
			}
		} catch ( Exception e ) {
			throw new IllegalArgumentException(e);
		}
	}
	
	/**
	 * Validates that the check number doesn't contain path traversal sequences
	 * and ensures the resulting path is within the intended directory.
	 *
	 * @param checkNumber The check number to validate
	 * @return True if the check number is valid, false otherwise
	 */
	private boolean isValidCheckNumber(String checkNumber) {
		if (checkNumber == null || checkNumber.isEmpty()) {
			return false;
		}
		
		// Normalize base path and combined path
		File baseDir = new File(CHECK_IMAGE_LOCATION).getAbsoluteFile();
		Path basePath = baseDir.toPath().normalize();
		Path requestedPath = Paths.get(baseDir.getPath(), checkNumber).normalize();
		
		// Ensure the requested path is within the base directory
		return requestedPath.startsWith(basePath);
	}

	public void findCheckImage(String checkNumber, OutputStream os) {
		// Validate the check number to prevent path traversal
		if (!isValidCheckNumber(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number");
		}
		
		try ( FileInputStream fis = new FileInputStream(new File(CHECK_IMAGE_LOCATION, checkNumber)) ) {
			byte[] b = new byte[1024];
			int read;
			while ( ( read = fis.read(b) ) != -1 ) {
				os.write(b, 0, read);
			}
		} catch ( IOException e ) {
			throw new IllegalArgumentException(e);
		}
	}
}
