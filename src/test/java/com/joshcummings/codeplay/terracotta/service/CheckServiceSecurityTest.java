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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.testng.Assert.*;

public class CheckServiceSecurityTest {

    private CheckService checkService;
    private static final String CHECK_IMAGE_LOCATION = "images/checks";
    
    @BeforeMethod
    public void setup() {
        checkService = new CheckService();
        // Ensure the directory exists
        new File(CHECK_IMAGE_LOCATION).mkdirs();
        
        // Create a test file in the checks directory
        try {
            File testFile = new File(CHECK_IMAGE_LOCATION, "valid-test-check");
            Files.write(testFile.toPath(), "test content".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    @Test
    public void testFindCheckImageWithValidPath() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Should succeed with a valid check number
        checkService.findCheckImage("valid-test-check", baos);
        
        assertTrue(baos.size() > 0, "Should return check image contents");
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageWithPathTraversalAttempt() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Should throw IllegalArgumentException for path traversal attempt
        checkService.findCheckImage("../../../etc/passwd", baos);
        
        // We should never reach this line
        fail("Path traversal protection failed");
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testFindCheckImageWithNormalizedPathTraversalAttempt() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Should throw IllegalArgumentException for normalized path traversal attempt
        checkService.findCheckImage("dummy/../../etc/passwd", baos);
        
        // We should never reach this line
        fail("Path traversal protection failed");
    }
    
    @Test
    public void testUpdateCheckImageWithValidPath() {
        String testContent = "test update content";
        ByteArrayInputStream bais = new ByteArrayInputStream(testContent.getBytes());
        
        // Should succeed with a valid check number
        checkService.updateCheckImage("test-update-check", bais);
        
        // Verify the file was created properly
        File createdFile = new File(CHECK_IMAGE_LOCATION, "test-update-check");
        assertTrue(createdFile.exists(), "File should have been created");
        
        // Clean up
        createdFile.delete();
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testUpdateCheckImageWithPathTraversalAttempt() {
        String testContent = "malicious content";
        ByteArrayInputStream bais = new ByteArrayInputStream(testContent.getBytes());
        
        // Should throw IllegalArgumentException for path traversal attempt
        checkService.updateCheckImage("../../../etc/passwd", bais);
        
        // We should never reach this line
        fail("Path traversal protection failed");
    }
}