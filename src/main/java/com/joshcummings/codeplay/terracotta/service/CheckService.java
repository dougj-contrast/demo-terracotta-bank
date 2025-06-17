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
		// First validate the base check number
		if (checkNumber == null || checkNumber.isEmpty()) {
			throw new IllegalArgumentException("Invalid check number");
		}
		
		// Remove any characters that aren't alphanumeric, hyphen, or underscore
		String sanitizedBaseNumber = checkNumber.replaceAll("[^a-zA-Z0-9\\-_]", "");
		
		// If sanitization changed the input, it was potentially malicious
		if (!sanitizedBaseNumber.equals(checkNumber)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ((ze = zis.getNextEntry()) != null) {
				try {
					// Get just the filename part without any path
					String entryFileName = new File(ze.getName()).getName();
					// Create a safe combined name
					String safeFileName = sanitizedBaseNumber + "_" + entryFileName;
					updateCheckImage(safeFileName, zis);
				} catch (Exception e) {
					e.printStackTrace(); // try to upload the other ones
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void updateCheckImage(String checkNumber, InputStream is) {
		try {
			File checkFile = validateFilePath(CHECK_IMAGE_LOCATION, checkNumber);
			try (FileOutputStream fos = new FileOutputStream(checkFile)) {
				byte[] b = new byte[1024];
				int read;
				while ((read = is.read(b)) != -1) {
					fos.write(b, 0, read);
				}
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	/**
	 * Validates that a path is safe and doesn't allow directory traversal
	 * @param basePath The base directory path
	 * @param userInput The user-provided path component
	 * @return A validated, safe file path
	 * @throws IllegalArgumentException if path traversal is detected
	 */
	private File validateFilePath(String basePath, String userInput) {
		if (userInput == null || userInput.isEmpty()) {
			throw new IllegalArgumentException("Invalid check number");
		}
		
		// Remove any characters that aren't alphanumeric, hyphen, or underscore
		String sanitizedInput = userInput.replaceAll("[^a-zA-Z0-9\\-_]", "");
		
		// If sanitization changed the input, it was potentially malicious
		if (!sanitizedInput.equals(userInput)) {
			throw new IllegalArgumentException("Invalid check number format");
		}
		
		Path baseDirPath = Paths.get(basePath).toAbsolutePath();
		Path resolvedPath = baseDirPath.resolve(sanitizedInput).toAbsolutePath();
		
		// Ensure the resolved path is still within the base directory
		if (!resolvedPath.startsWith(baseDirPath)) {
			throw new IllegalArgumentException("Path traversal detected");
		}
		
		return resolvedPath.toFile();
	}
	
	public void findCheckImage(String checkNumber, OutputStream os) {
		try {
			File checkFile = validateFilePath(CHECK_IMAGE_LOCATION, checkNumber);
			try (FileInputStream fis = new FileInputStream(checkFile)) {
				byte[] b = new byte[1024];
				int read;
				while ((read = fis.read(b)) != -1) {
					os.write(b, 0, read);
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
