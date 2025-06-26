/*
 * Copyright 2015-2023 Josh Cummings
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

import com.joshcummings.codeplay.terracotta.model.User;
import com.joshcummings.codeplay.terracotta.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.apache.http.client.methods.RequestBuilder.post;

public class UserServiceSecurityTest extends AbstractEmbeddedTomcatTest {
    
    @Test(groups="security")
    public void testSqlInjectionPrevention() {
        // Attempt SQL injection in login parameters
        String maliciousUsername = "admin' --";
        String anyPassword = "doesnt_matter"; // With SQL injection, this would be ignored
        
        String content = http.postForContent(post("/login")
                .addParameter("username", maliciousUsername)
                .addParameter("password", anyPassword));
        
        // If our fix worked, the SQL injection attempt should fail and return the login error
        Assert.assertTrue(content.contains("incorrect"), 
                "SQL Injection prevention should cause login to fail");
        
        // Ensure legitimate login still works
        String legitimateContent = http.postForContent(post("/login")
                .addParameter("username", "admin")
                .addParameter("password", "admin"));
                
        Assert.assertTrue(legitimateContent.contains("Welcome"), 
                "Legitimate login should still work after fix");
    }
    
    @Test(groups="security") 
    public void testMultipleSqlInjectionAttempts() {
        // Test various SQL injection payloads
        String[] injectionPayloads = {
            "admin' --",
            "admin' OR '1'='1",
            "admin'; SELECT * FROM users; --",
            "' OR 1=1; --"
        };
        
        for (String payload : injectionPayloads) {
            String content = http.postForContent(post("/login")
                    .addParameter("username", payload)
                    .addParameter("password", "anything"));
            
            Assert.assertTrue(content.contains("incorrect"),
                    "SQL Injection payload '" + payload + "' should be blocked");
        }
    }
}