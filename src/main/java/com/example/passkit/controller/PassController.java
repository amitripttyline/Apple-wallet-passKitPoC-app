package com.example.passkit.controller;

import java.util.Map;
import com.example.passkit.service.PassGeneratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/pass")
@CrossOrigin(origins = "*")
public class PassController {

    private static final Logger logger = LoggerFactory.getLogger(PassController.class);

    @Autowired
    private PassGeneratorService passGeneratorService;

    @GetMapping("/generate")
    public ResponseEntity<?> generatePass() {
        try {
            PassGeneratorService.PassGenerationResult result = passGeneratorService.generatePass();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(result.getData().length);
            headers.add("X-Pass-Serial-Number", result.getSerialNumber());

            return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error generating pass", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to generate pass: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Create a new pass with auto-generated ID and specified type (short code).
     * Supports both POST (API) and GET (Browser) requests.
     * 
     * @param type Pass type code (bp, cp, ep, sp, gp)
     */
    @RequestMapping(value = "", method = { RequestMethod.POST, RequestMethod.GET })
    public ResponseEntity<?> createPass(@RequestParam(required = false) String type) {
        try {
            PassGeneratorService.PassGenerationResult result = passGeneratorService.generatePass(null, type);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(result.getData().length);
            headers.add("X-Pass-Serial-Number", result.getSerialNumber());

            return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error generating pass", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to generate pass: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Generate a pass with specific serial number (URL parameter)
     * 
     * @param type Optional pass type (BOARDING, COUPON, EVENT, STORE, GENERIC)
     */
    @RequestMapping(value = "/{serialNumber}", method = { RequestMethod.POST, RequestMethod.GET })
    public ResponseEntity<?> createPassWithId(
            @PathVariable String serialNumber,
            @RequestParam(required = false) String type) {
        try {
            // If it's a GET request and we are just requesting by ID, try to get existing
            // first
            PassGeneratorService.PassGenerationResult result;

            result = passGeneratorService.getUpdatedPass(serialNumber);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(result.getData().length);
            headers.add("X-Pass-Serial-Number", result.getSerialNumber());

            return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
        } catch (Exception e) {
            // If not found and we have type or it's a creation intent, could fallback to
            // generate from static template
            try {
                PassGeneratorService.PassGenerationResult result = passGeneratorService
                        .generatePass(serialNumber, type);
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
                headers.setContentDispositionFormData("attachment", "pass.pkpass");
                headers.setContentLength(result.getData().length);
                headers.add("X-Pass-Serial-Number", result.getSerialNumber());
                return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
            } catch (Exception ex) {
                logger.error("Error generating pass with ID: {}", serialNumber, ex);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Failed to generate pass: " + ex.getMessage() + "\"}");
            }
        }
    }

    /**
     * Update an existing pass
     */
    @PutMapping("/{serialNumber}")
    public ResponseEntity<?> updatePass(
            @PathVariable String serialNumber,
            @RequestBody(required = false) com.example.passkit.dto.PassRequest request) {
        try {
            PassGeneratorService.PassGenerationResult result;
            if (request == null) {
                // Refresh existing pass (preserve type/data)
                result = passGeneratorService.getUpdatedPass(serialNumber);
            } else {
                // Update with new data
                result = passGeneratorService.generatePass(serialNumber, request);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(result.getData().length);
            headers.add("X-Pass-Serial-Number", result.getSerialNumber());

            return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error updating pass: {}", serialNumber, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to update pass: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Revoke a pass (soft delete)
     */
    @DeleteMapping("/{serialNumber}")
    public ResponseEntity<?> revokePass(@PathVariable String serialNumber) {
        try {
            passGeneratorService.revokePass(serialNumber);
            return ResponseEntity.ok("{\"message\":\"Pass revoked successfully\"}");
        } catch (Exception e) {
            logger.error("Error revoking pass: {}", serialNumber, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to revoke pass: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Expire a pass
     */
    @PostMapping("/{serialNumber}/expire")
    public ResponseEntity<?> expirePass(@PathVariable String serialNumber) {
        try {
            passGeneratorService.expirePass(serialNumber);
            return ResponseEntity.ok("{\"message\":\"Pass expired successfully\"}");
        } catch (Exception e) {
            logger.error("Error expiring pass: {}", serialNumber, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to expire pass: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("PassKit Backend is running");
    }

    /**
     * Update an existing pass using query parameters.
     * Example: /api/pass/{serialNumber}/details?seat=1A&status=active
     */
    @PutMapping("/{serialNumber}/details")
    public ResponseEntity<?> updatePassWithParams(
            @PathVariable String serialNumber,
            @RequestParam Map<String, String> allParams) {
        try {
            PassGeneratorService.PassGenerationResult result = passGeneratorService.updatePassFromParams(serialNumber,
                    allParams);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentDispositionFormData("attachment", "pass.pkpass");
            headers.setContentLength(result.getData().length);
            headers.add("X-Pass-Serial-Number", result.getSerialNumber());

            return new ResponseEntity<>(result.getData(), headers, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error updating pass from params: {}", serialNumber, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Failed to update pass: " + e.getMessage() + "\"}");
        }
    }
}
