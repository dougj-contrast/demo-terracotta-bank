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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.testng.Assert.fail;

public class CheckServiceSecurityTest {

    private CheckService checkService;
    private static final String TEST_CONTENT = "test content";

    @BeforeMethod
    public void setUp() {
        checkService = new CheckService();
    }

    @Test
    public void testFindCheckImage_withPathTraversalAttempt_shouldThrowException() {
        // Test various path traversal patterns
        String[] maliciousPaths = {
            "../../../etc/passwd", 
            "..\\..\\Windows\\System32\\config\\sam", 
            "/etc/passwd", 
            "C:\\Windows\\System32\\config\\sam"
        };

        for (String path : maliciousPaths) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try {
                checkService.findCheckImage(path, output);
                fail("Should have thrown exception for path: " + path);
            } catch (IllegalArgumentException e) {
                // Expected exception
            }
        }
    }

    @Test
    public void testUpdateCheckImage_withPathTraversalAttempt_shouldThrowException() {
        // Test various path traversal patterns
        String[] maliciousPaths = {
            "../../../etc/passwd", 
            "..\\..\\Windows\\System32\\config\\sam", 
            "/etc/passwd", 
            "C:\\Windows\\System32\\config\\sam"
        };

        byte[] testData = TEST_CONTENT.getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream input = new ByteArrayInputStream(testData);

        for (String path : maliciousPaths) {
            try {
                checkService.updateCheckImage(path, input);
                fail("Should have thrown exception for path: " + path);
            } catch (IllegalArgumentException e) {
                // Expected exception
            }
            // Reset the input stream for the next iteration
            input.reset();
        }
    }

    @Test
    public void testUpdateCheckImagesBulk_withPathTraversalInZipEntry_shouldThrowException() throws IOException {
        // Create a ZIP with malicious entry names
        ByteArrayOutputStream zipBuffer = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(zipBuffer)) {
            // Add a malicious ZIP entry
            ZipEntry entry = new ZipEntry("../../../etc/passwd");
            zos.putNextEntry(entry);
            zos.write(TEST_CONTENT.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        // Test the ZIP with malicious entry
        ByteArrayInputStream zipInput = new ByteArrayInputStream(zipBuffer.toByteArray());
        try {
            checkService.updateCheckImagesBulk("validCheckNumber", zipInput);
            fail("Should have thrown exception for malicious ZIP entry");
        } catch (IllegalArgumentException e) {
            // Expected exception
        }
    }

    @Test
    public void testUpdateCheckImage_withValidPath_shouldSucceed() throws IOException {
        // Create a temporary directory for testing
        File tempDir = new File("images/checks").getAbsoluteFile();
        tempDir.mkdirs();
        
        try {
            // Test with a valid check number
            String validCheckNumber = "12345";
            byte[] testData = TEST_CONTENT.getBytes(StandardCharsets.UTF_8);
            ByteArrayInputStream input = new ByteArrayInputStream(testData);
            
            checkService.updateCheckImage(validCheckNumber, input);
            
            // Verify the file was created
            File createdFile = new File(tempDir, validCheckNumber);
            if (!createdFile.exists()) {
                fail("File was not created");
            }
            
            // Clean up - delete the file
            createdFile.delete();
        } finally {
            // Clean up any test files that might have been created
            // Note: in a real test environment, we would use a dedicated test directory
        }
    }
}