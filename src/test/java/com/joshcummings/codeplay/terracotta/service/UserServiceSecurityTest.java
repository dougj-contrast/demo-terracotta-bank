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

import com.joshcummings.codeplay.terracotta.model.User;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class UserServiceSecurityTest {
	private UserService userService;

	@BeforeClass
	public void setup() {
		userService = new UserService();
		User testUser = new User("test-id", "testuser", "testpass", "Test User", "test@example.com", false);
		userService.addUser(testUser);
	}

	@Test
	public void testSqlInjectionInUsername() {
		String maliciousUsername = "admin' OR '1'='1";
		String password = "wrongpassword";

		User result = userService.findByUsernameAndPassword(maliciousUsername, password);

		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test
	public void testSqlInjectionInPassword() {
		String username = "testuser";
		String maliciousPassword = "' OR '1'='1";

		User result = userService.findByUsernameAndPassword(username, maliciousPassword);

		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test
	public void testSqlInjectionInBothParameters() {
		String maliciousUsername = "admin' OR '1'='1' --";
		String maliciousPassword = "' OR '1'='1";

		User result = userService.findByUsernameAndPassword(maliciousUsername, maliciousPassword);

		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test
	public void testValidCredentials() {
		String username = "testuser";
		String password = "testpass";

		User result = userService.findByUsernameAndPassword(username, password);

		Assert.assertNotNull(result, "Valid credentials should return a user");
		Assert.assertEquals(result.getUsername(), username);
	}

	@Test
	public void testInvalidCredentials() {
		String username = "testuser";
		String password = "wrongpassword";

		User result = userService.findByUsernameAndPassword(username, password);

		Assert.assertNull(result, "Invalid credentials should not return a user");
	}

	@Test
	public void testSpecialCharactersInUsername() {
		String username = "test'user";
		String password = "testpass";

		User result = userService.findByUsernameAndPassword(username, password);

		Assert.assertNull(result, "Username with special characters should be handled safely");
	}
}
