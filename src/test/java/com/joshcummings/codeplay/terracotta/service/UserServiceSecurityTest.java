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

import static org.apache.http.client.methods.RequestBuilder.post;

public class UserServiceSecurityTest extends AbstractEmbeddedTomcatTest {

	@Test(groups="data")
	public void testSqlInjectionInUsernameBlocked() {
		String maliciousUsername = "admin' OR '1'='1";
		String password = "wrongpassword";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", maliciousUsername)
				.addParameter("password", password));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should not succeed");
		Assert.assertFalse(content.contains("Welcome"), 
			"Should not be logged in with SQL injection attempt");
	}

	@Test(groups="data")
	public void testSqlInjectionInPasswordBlocked() {
		String username = "admin";
		String maliciousPassword = "' OR '1'='1";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", username)
				.addParameter("password", maliciousPassword));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should not succeed");
		Assert.assertFalse(content.contains("Welcome"), 
			"Should not be logged in with SQL injection attempt");
	}

	@Test(groups="data")
	public void testSqlInjectionInBothFieldsBlocked() {
		String maliciousUsername = "admin' --";
		String maliciousPassword = "anything";
		
		String content = http.postForContent(post("/login")
				.addParameter("username", maliciousUsername)
				.addParameter("password", maliciousPassword));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should not succeed");
		Assert.assertFalse(content.contains("Welcome"), 
			"Should not be logged in with SQL injection attempt");
	}

	@Test(groups="data")
	public void testValidLoginStillWorks() {
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin")
				.addParameter("password", "admin"));

		Assert.assertTrue(content.contains("Welcome"), 
			"Valid login should still work after fix");
	}
}
