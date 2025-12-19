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

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;
import com.joshcummings.codeplay.terracotta.model.User;
import org.testng.Assert;
import org.testng.annotations.Test;

public class UserServiceSecurityTest extends AbstractEmbeddedTomcatTest {

	@Test(groups="data")
	public void testSqlInjectionInUsername() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin' OR '1'='1", "wrongpassword");
		
		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test(groups="data")
	public void testSqlInjectionInPassword() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin", "' OR '1'='1");
		
		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test(groups="data")
	public void testSqlInjectionInBothParameters() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin' OR '1'='1' --", "anything");
		
		Assert.assertNull(result, "SQL injection attempt should not return a user");
	}

	@Test(groups="data")
	public void testValidCredentialsStillWork() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin", "admin");
		
		Assert.assertNotNull(result, "Valid credentials should return a user");
		Assert.assertEquals(result.getUsername(), "admin");
		Assert.assertEquals(result.getName(), "Admin Admin");
	}

	@Test(groups="data")
	public void testInvalidCredentialsReturnNull() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin", "wrongpassword");
		
		Assert.assertNull(result, "Invalid credentials should return null");
	}

	@Test(groups="data")
	public void testSpecialCharactersInCredentials() {
		UserService userService = context.getBean(UserService.class);
		
		User result = userService.findByUsernameAndPassword("admin'; DROP TABLE users; --", "password");
		
		Assert.assertNull(result, "SQL injection with DROP TABLE should not succeed");
	}
}
