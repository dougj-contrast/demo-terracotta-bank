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
package com.joshcummings.codeplay.terracotta.service;

import com.joshcummings.codeplay.terracotta.AbstractEmbeddedTomcatTest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class CheckServiceSecurityTest extends AbstractEmbeddedTomcatTest {
    private CheckService checkService;
    
    @BeforeMethod(alwaysRun = true)
    public void setupCheckService() {
        checkService = new CheckService();
    }
    
    @Test(groups = "security", expectedExceptions = IllegalArgumentException.class, 
          expectedExceptionsMessageRegExp = "Invalid check number format")
    public void testPathTraversalWithTraversalSequence() {
        // Attempt to access a file outside the intended directory using "../"
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage("../sensitive/file", baos);
    }
    
    @Test(groups = "security", expectedExceptions = IllegalArgumentException.class, 
          expectedExceptionsMessageRegExp = "Invalid check number format")
    public void testPathTraversalWithAbsolutePath() {
        // Attempt to access a file using an absolute path
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage("/etc/passwd", baos);
    }
    
    @Test(groups = "security", expectedExceptions = IllegalArgumentException.class, 
          expectedExceptionsMessageRegExp = "Invalid check number format")
    public void testPathTraversalWithEmptyString() {
        // Test with an empty string
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage("", baos);
    }
    
    @Test(groups = "security", expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithNullValue() {
        // Test with null value
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage(null, baos);
    }
    
    @Test(groups = "security", expectedExceptions = IllegalArgumentException.class, 
          expectedExceptionsMessageRegExp = "Invalid check number format")
    public void testPathTraversalWithWindowsBackslash() {
        // Attempt to use Windows path syntax
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        checkService.findCheckImage("folder\\file", baos);
    }
    
    @Test(groups = "security")
    public void testValidCheckNumberAccess() {
        // This test would require a valid check file to exist
        // Skip actual file operations as they depend on the environment
        // Just verify that a valid check number format passes validation
        try {
            // Use reflection to test the private isValidCheckNumber method
            java.lang.reflect.Method method = CheckService.class.getDeclaredMethod("isValidCheckNumber", String.class);
            method.setAccessible(true);
            boolean result = (boolean) method.invoke(checkService, "12345");
            Assert.assertTrue(result, "Valid check number should pass validation");
        } catch (Exception e) {
            Assert.fail("Exception while testing valid check number", e);
        }
    }
}