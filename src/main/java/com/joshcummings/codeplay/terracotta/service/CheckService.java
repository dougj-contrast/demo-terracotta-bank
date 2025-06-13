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
		try (ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry ze;
			while ( (ze = zis.getNextEntry()) != null ) {
				try {
					updateCheckImage(checkNumber + "/" + ze.getName(), zis);
				} catch ( Exception e ) {
					e.printStackTrace(); // try to upload the other ones
				}
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void updateCheckImage(String checkNumber, InputStream is) {
		File baseDir = new File(CHECK_IMAGE_LOCATION);
		try {
			File targetFile = new File(baseDir, checkNumber);
			
			// Validate that the target file is within the intended directory
			String canonicalBasePath = baseDir.getCanonicalPath();
			String canonicalTargetPath = targetFile.getCanonicalPath();
			
			if (!canonicalTargetPath.startsWith(canonicalBasePath + File.separator) &&
				!canonicalTargetPath.equals(canonicalBasePath)) {
				throw new IllegalArgumentException("Invalid check number");
			}
			
			// Create parent directories if they don't exist
			File parentDir = targetFile.getParentFile();
			if (!parentDir.exists()) {
				parentDir.mkdirs();
			}
			
			try (FileOutputStream fos = new FileOutputStream(targetFile)) {
				byte[] b = new byte[1024];
				int read;
				while ((read = is.read(b)) != -1) {
					fos.write(b, 0, read);
				}
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public void findCheckImage(String checkNumber, OutputStream os) {
		File baseDir = new File(CHECK_IMAGE_LOCATION);
		try {
			File requestedFile = new File(baseDir, checkNumber);
			
			// Validate that the requested file is within the intended directory
			String canonicalBasePath = baseDir.getCanonicalPath();
			String canonicalRequestedPath = requestedFile.getCanonicalPath();
			
			if (!canonicalRequestedPath.startsWith(canonicalBasePath + File.separator) &&
				!canonicalRequestedPath.equals(canonicalBasePath)) {
				throw new IllegalArgumentException("Invalid check number");
			}
			
			try (FileInputStream fis = new FileInputStream(requestedFile)) {
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
