package com.example.passkit.controller;

import com.example.passkit.service.PassGeneratorService;
import com.example.passkit.service.PassRegistrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Apple Wallet Web Service Protocol endpoints
 * https://developer.apple.com/documentation/walletpasses/adding_a_web_service_to_update_passes
 */
@RestController
@RequestMapping("/v1")
@CrossOrigin(origins = "*")
public class WalletWebServiceController {

    private static final Logger logger = LoggerFactory.getLogger(WalletWebServiceController.class);

    @Autowired
    private PassRegistrationService registrationService;

    @Autowired
    private PassGeneratorService passGeneratorService;

    @Value("${passkit.auth.token:}")
    private String expectedAuthToken;

    /**
     * Register a device to receive push notifications for a pass
     * POST /v1/devices/{deviceId}/registrations/{passTypeId}/{serialNumber}
     */
    @PostMapping("/devices/{deviceId}/registrations/{passTypeId}/{serialNumber}")
    public ResponseEntity<?> registerDevice(
            @PathVariable String deviceId,
            @PathVariable String passTypeId,
            @PathVariable String serialNumber,
            @RequestBody Map<String, String> requestBody,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        logger.info("Device registration request: deviceId={}, passTypeId={}, serialNumber={}",
                deviceId, passTypeId, serialNumber);

        // Validate authentication token
        if (!validateAuthToken(authHeader)) {
            logger.warn("Invalid authentication token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            String pushToken = requestBody.get("pushToken");

            if (pushToken == null || pushToken.isEmpty()) {
                logger.warn("Missing pushToken in request body");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "pushToken is required"));
            }

            registrationService.registerDevice(deviceId, passTypeId, serialNumber, pushToken);

            // Return 201 for new registration, 200 if already registered
            return ResponseEntity.status(HttpStatus.CREATED).build();

        } catch (Exception e) {
            logger.error("Error registering device", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Unregister a device for pass updates
     * DELETE /v1/devices/{deviceId}/registrations/{passTypeId}/{serialNumber}
     */
    @DeleteMapping("/devices/{deviceId}/registrations/{passTypeId}/{serialNumber}")
    public ResponseEntity<?> unregisterDevice(
            @PathVariable String deviceId,
            @PathVariable String passTypeId,
            @PathVariable String serialNumber,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        logger.info("Device unregistration request: deviceId={}, passTypeId={}, serialNumber={}",
                deviceId, passTypeId, serialNumber);

        // Validate authentication token
        if (!validateAuthToken(authHeader)) {
            logger.warn("Invalid authentication token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            boolean removed = registrationService.unregisterDevice(deviceId, passTypeId, serialNumber);

            if (removed) {
                return ResponseEntity.ok().build();
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

        } catch (Exception e) {
            logger.error("Error unregistering device", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get serial numbers for passes that have changed since a given date
     * GET
     * /v1/devices/{deviceId}/registrations/{passTypeId}?passesUpdatedSince=<tag>
     */
    @GetMapping("/devices/{deviceId}/registrations/{passTypeId}")
    public ResponseEntity<?> getSerialNumbers(
            @PathVariable String deviceId,
            @PathVariable String passTypeId,
            @RequestParam(required = false) String passesUpdatedSince,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        logger.info("Get serial numbers request: deviceId={}, passTypeId={}, passesUpdatedSince={}",
                deviceId, passTypeId, passesUpdatedSince);

        // Validate authentication token
        if (!validateAuthToken(authHeader)) {
            logger.warn("Invalid authentication token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            List<String> serialNumbers = registrationService
                    .getRegisteredSerialNumbers(deviceId, passTypeId);

            if (serialNumbers.isEmpty()) {
                return ResponseEntity.noContent().build();
            }

            // Return current timestamp as lastUpdated tag
            String currentTag = LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME);

            Map<String, Object> response = Map.of(
                    "serialNumbers", serialNumbers,
                    "lastUpdated", currentTag);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error getting serial numbers", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get the latest version of a pass
     * GET /v1/passes/{passTypeId}/{serialNumber}
     */
    @GetMapping("/passes/{passTypeId}/{serialNumber}")
    public ResponseEntity<?> getPass(
            @PathVariable String passTypeId,
            @PathVariable String serialNumber,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "If-Modified-Since", required = false) String ifModifiedSince) {

        logger.info("Get pass request: passTypeId={}, serialNumber={}, ifModifiedSince={}",
                passTypeId, serialNumber, ifModifiedSince);

        // Validate authentication token
        if (!validateAuthToken(authHeader)) {
            logger.warn("Invalid authentication token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            // TODO: Implement If-Modified-Since logic to return 304 Not Modified if pass
            // hasn't changed
            // For now, always return the pass

            PassGeneratorService.PassGenerationResult result = passGeneratorService.getUpdatedPass(serialNumber);
            byte[] pkpassData = result.getData();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/vnd.apple.pkpass"));
            headers.setContentLength(pkpassData.length);
            headers.setLastModified(System.currentTimeMillis());

            return new ResponseEntity<>(pkpassData, headers, HttpStatus.OK);

        } catch (Exception e) {
            logger.error("Error getting pass: {}", e.getMessage());
            if (e.getMessage().contains("not found") || e.getMessage().contains("not active")) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Log error messages from devices
     * POST /v1/log
     */
    @PostMapping("/log")
    public ResponseEntity<?> logError(@RequestBody Map<String, Object> logs) {
        logger.info("Device log received: {}", logs);
        // In production, store these logs for debugging
        return ResponseEntity.ok().build();
    }

    /**
     * Validate the authentication token
     */
    private boolean validateAuthToken(String authHeader) {
        if (expectedAuthToken == null || expectedAuthToken.isEmpty()) {
            // If no token is configured, deny requests by default for security
            // To allow unauthenticated access in development, explicitly set an empty token
            logger.error("SECURITY WARNING: No authentication token configured. Denying request.");
            logger.error("To allow development access, set passkit.auth.token=dev-bypass in application.properties");
            return false;
        }

        // Allow bypass in development mode with special token
        if ("dev-bypass".equals(expectedAuthToken)) {
            logger.warn("Development mode: Authentication bypassed");
            return true;
        }

        if (authHeader == null || authHeader.isEmpty()) {
            return false;
        }

        // Expected format: "ApplePass <token>"
        String token = authHeader.replace("ApplePass ", "").trim();
        return expectedAuthToken.equals(token);
    }
}
