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
package com.joshcummings.codeplay.terracotta;

import org.testng.Assert;
import org.testng.annotations.Test;

import static org.apache.http.client.methods.RequestBuilder.post;

public class LoginServletSecurityTest extends AbstractEmbeddedTomcatTest {

	@Test(groups="data")
	public void testSqlInjectionInUsernameBlocked() {
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin' OR '1'='1")
				.addParameter("password", "anything"));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should fail authentication");
		Assert.assertFalse(content.contains("Welcome"), 
			"SQL injection should not bypass authentication");
	}

	@Test(groups="data")
	public void testSqlInjectionInPasswordBlocked() {
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin")
				.addParameter("password", "' OR '1'='1"));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should fail authentication");
		Assert.assertFalse(content.contains("Welcome"), 
			"SQL injection should not bypass authentication");
	}

	@Test(groups="data")
	public void testSqlInjectionInBothFieldsBlocked() {
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin' --")
				.addParameter("password", "anything"));

		Assert.assertTrue(content.contains("provided is incorrect"), 
			"SQL injection attempt should fail authentication");
		Assert.assertFalse(content.contains("Welcome"), 
			"SQL injection should not bypass authentication");
	}

	@Test(groups="data")
	public void testValidLoginStillWorks() {
		String content = http.postForContent(post("/login")
				.addParameter("username", "admin")
				.addParameter("password", "admin"));

		Assert.assertTrue(content.contains("Welcome, Admin Admin!"), 
			"Valid credentials should still work after SQL injection fix");
	}
}
