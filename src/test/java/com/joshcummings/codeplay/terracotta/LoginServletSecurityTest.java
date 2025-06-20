package com.joshcummings.codeplay.terracotta;

import com.joshcummings.codeplay.terracotta.model.User;
import com.joshcummings.codeplay.terracotta.service.UserService;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * This security test verifies the fix for the SQL Injection vulnerability in LoginServlet.
 * It tests that SQL injection attempts through the username and password parameters are properly prevented.
 */
public class LoginServletSecurityTest extends AbstractEmbeddedTomcatTest {
    
    @Test
    public void testSqlInjectionInLogin() {
        // Create a legitimate user for testing
        UserService userService = this.context.getBean(UserService.class);
        User legitimateUser = new User("testuser", "Test User", "user@test.com", "testuser", "password123", false);
        userService.addUser(legitimateUser);
        
        // Test SQL injection in username
        String maliciousUsername = "' OR '1'='1";
        String password = "anything";
        User resultUser = userService.findByUsernameAndPassword(maliciousUsername, password);
        
        // If SQL injection is prevented, no user should be found
        Assert.assertNull(resultUser, "SQL Injection prevention should return null for malicious username");
        
        // Test SQL injection in password
        String username = "testuser";
        String maliciousPassword = "' OR '1'='1";
        resultUser = userService.findByUsernameAndPassword(username, maliciousPassword);
        
        // If SQL injection is prevented, no user should be found with incorrect password
        Assert.assertNull(resultUser, "SQL Injection prevention should return null for malicious password");
        
        // Verify legitimate login still works
        resultUser = userService.findByUsernameAndPassword("testuser", "password123");
        Assert.assertNotNull(resultUser, "Legitimate login should still work");
        Assert.assertEquals(resultUser.getUsername(), "testuser");
    }
}