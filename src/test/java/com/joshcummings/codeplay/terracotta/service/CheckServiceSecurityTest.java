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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Tests that verify the path traversal vulnerability has been fixed
 * in CheckService.
 */
public class CheckServiceSecurityTest {
    private CheckService checkService;

    @BeforeMethod
    public void setUp() {
        checkService = new CheckService();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithDotsInFindCheckImage() {
        // Attempt path traversal with "../" to access files outside the intended directory
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        checkService.findCheckImage("../../../passwd", outputStream);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithForwardSlashInFindCheckImage() {
        // Attempt path traversal with direct path
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        checkService.findCheckImage("/etc/passwd", outputStream);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithBackslashInFindCheckImage() {
        // Attempt path traversal with backslash
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        checkService.findCheckImage("..\\..\\..\\Windows\\System32\\config\\SAM", outputStream);
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithDotsInUpdateCheckImage() {
        // Test path traversal prevention in updateCheckImage
        InputStream mockInputStream = new java.io.ByteArrayInputStream("test".getBytes());
        checkService.updateCheckImage("../../../passwd", mockInputStream);
    }
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testPathTraversalWithDotsInUpdateCheckImagesBulk() {
        // Test path traversal prevention in updateCheckImagesBulk
        InputStream mockInputStream = new java.io.ByteArrayInputStream("test".getBytes());
        checkService.updateCheckImagesBulk("../../../passwd", mockInputStream);
    }

    @Test
    public void testValidCheckNumberAccepted() {
        // Test that valid check numbers still work
        // Note: This test assumes the file exists, which it won't in the test context
        // This is just to demonstrate that valid paths would be accepted
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            checkService.findCheckImage("123456", outputStream);
        } catch (IllegalArgumentException e) {
            // Expected due to file not existing, but we should not get the "Invalid check number format" message
            assert !e.getMessage().contains("Invalid check number format");
        }
    }
}