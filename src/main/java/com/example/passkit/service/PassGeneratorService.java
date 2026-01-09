package com.example.passkit.service;

import com.example.passkit.model.PassMetadata;
import com.example.passkit.repository.PassMetadataRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class PassGeneratorService {

    private static final Logger logger = LoggerFactory.getLogger(PassGeneratorService.class);

    @Value("${passkit.certificate.path:Apple-wallet-passKitPoC-app/certs/pass-certificate.pem}")
    private String certificatePath;

    @Value("${passkit.privatekey.path:Apple-wallet-passKitPoC-app/certs/pass-private-key.pem}")
    private String privateKeyPath;

    @Value("${passkit.wwdr.path:Apple-wallet-passKitPoC-app/certs/wwdr.pem}")
    private String wwdrPath;

    @Value("${passkit.pass.typeIdentifier:pass.com.example.passkit}")
    private String passTypeIdentifier;

    @Value("${passkit.pass.teamIdentifier:YOUR_TEAM_ID}")
    private String teamIdentifier;

    @Value("${passkit.pass.organizationName:Example Organization}")
    private String organizationName;

    @Value("${passkit.webservice.url:}")
    private String webServiceURL;

    @Value("${passkit.auth.token:}")
    private String authenticationToken;

    @Autowired
    private PassMetadataRepository passMetadataRepository;

    @Autowired
    private APNsService apnsService;

    private PrivateKey privateKey;
    private X509Certificate passCertificate;
    private X509Certificate wwdrCertificate;

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        // Certificates will be loaded when needed, or can be preloaded here
        // For now, we'll load them on demand to handle missing cert files gracefully
    }

    public static class PassGenerationResult {
        private final byte[] data;
        private final String serialNumber;

        public PassGenerationResult(byte[] data, String serialNumber) {
            this.data = data;
            this.serialNumber = serialNumber;
        }

        public byte[] getData() {
            return data;
        }

        public String getSerialNumber() {
            return serialNumber;
        }
    }

    public PassGenerationResult generatePass() throws Exception {
        return generatePass(null, (com.example.passkit.dto.PassRequest) null);
    }

    public PassGenerationResult generatePass(String serialNumber) throws Exception {
        return generatePass(serialNumber, (com.example.passkit.dto.PassRequest) null);
    }

    /**
     * Generate a pass with custom configuration
     */
    /**
     * Generate a pass with custom configuration
     */
    public PassGenerationResult generatePass(String serialNumber, String type) throws Exception {
        com.example.passkit.dto.PassRequest request = null;

        // If type is provided, load static template data
        if (type != null && !type.isEmpty()) {
            request = getStaticPassRequest(type);
        }

        return generatePass(serialNumber, request);
    }

    /**
     * Update pass from params
     */
    public PassGenerationResult updatePassFromParams(String serialNumber, Map<String, String> params) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        // Handle status update
        if (params.containsKey("status")) {
            String status = params.get("status");
            String newStatusLabel = "ACTIVE";
            if ("expired".equalsIgnoreCase(status)) {
                metadata.setStatus(PassMetadata.PassStatus.EXPIRED);
                newStatusLabel = "EXPIRED";
            } else if ("active".equalsIgnoreCase(status)) {
                metadata.setStatus(PassMetadata.PassStatus.ACTIVE);
                newStatusLabel = "ACTIVE";
            } else if ("inactive".equalsIgnoreCase(status) || "revoked".equalsIgnoreCase(status)) {
                metadata.setStatus(PassMetadata.PassStatus.REVOKED);
                newStatusLabel = "REVOKED";
            }
            passMetadataRepository.save(metadata);
            // Ensure the status parameter in the map is the descriptive label for injection
            params.put("status", newStatusLabel);
        }

        if (metadata.getStatus() == PassMetadata.PassStatus.REVOKED) {
            throw new Exception("Pass is revoked and cannot be updated.");
        }

        // Get existing pass json
        String json = metadata.getPassData();
        Map<String, Object> passJson = new ObjectMapper().readValue(json, Map.class);

        // Determine type to know which structure to update
        String type = detectTypeFromPassJson(json);

        // Update fields based on params
        updatePassJsonFields(passJson, type, params);

        // Regenerate pass
        String updatedJson = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(passJson);
        metadata.setPassData(updatedJson);
        metadata.incrementVersion();
        passMetadataRepository.save(metadata);

        // Create manifest and sign
        Map<String, String> manifest = createManifest(updatedJson);
        String manifestJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(manifest);
        byte[] signature = signManifest(manifestJsonString.getBytes(StandardCharsets.UTF_8));
        byte[] pkpass = createPkpassZip(updatedJson, manifestJsonString, signature);

        // Notify
        apnsService.notifyPassUpdate(passTypeIdentifier, serialNumber);

        return new PassGenerationResult(pkpass, serialNumber);
    }

    private void updatePassJsonFields(Map<String, Object> passJson, String type, Map<String, String> params) {
        // Map type string to json key
        String structureKey = "generic";
        if ("BOARDING".equals(type))
            structureKey = "boardingPass";
        else if ("COUPON".equals(type))
            structureKey = "coupon";
        else if ("EVENT".equals(type))
            structureKey = "eventTicket";
        else if ("STORE".equals(type))
            structureKey = "storeCard";

        Map<String, Object> structure = (Map<String, Object>) passJson.get(structureKey);
        if (structure == null)
            return;

        List<String> fieldCategories = Arrays.asList("primaryFields", "secondaryFields", "auxiliaryFields",
                "backFields");

        for (String category : fieldCategories) {
            List<Map<String, Object>> fields = (List<Map<String, Object>>) structure.get(category);
            if (fields != null) {
                for (Map<String, Object> field : fields) {
                    String key = (String) field.get("key");
                    if (key != null && params.containsKey(key)) {
                        field.put("value", params.get(key));
                    }
                }
            }
        }
    }

    /**
     * Generate a pass with custom configuration
     */
    public PassGenerationResult generatePass(String serialNumber, com.example.passkit.dto.PassRequest request)
            throws Exception {
        // Use provided serial number or generate new one
        if (serialNumber == null) {
            serialNumber = generate5DigitSerialNumber();
        }

        // If request is null and we don't have a type (called from legacy methods),
        // create default generic
        if (request == null) {
            request = getStaticPassRequest("GENERIC");
        }

        logger.info("Generating pass with serialNumber: {}, passTypeIdentifier: {}, teamIdentifier: {}",
                serialNumber, passTypeIdentifier, teamIdentifier);

        // Create pass.json
        Map<String, Object> passJson = createPassJson(serialNumber, request);
        String passJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(passJson);

        logger.debug("Created pass.json with identifiers - passTypeIdentifier: {}, teamIdentifier: {}",
                passTypeIdentifier, teamIdentifier);

        // Save or update pass metadata
        savePassMetadata(serialNumber, passJsonString);

        // Create manifest.json (include PNG files)
        Map<String, String> manifest = createManifest(passJsonString);
        String manifestJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(manifest);

        logger.debug("Created manifest.json with {} entries", manifest.size());

        // Sign manifest
        logger.info("Signing manifest with certificates...");
        byte[] signature = signManifest(manifestJsonString.getBytes(StandardCharsets.UTF_8));
        logger.info("Manifest signed successfully (signature size: {} bytes)", signature.length);

        // Create .pkpass zip file
        logger.info("Creating .pkpass zip file...");
        byte[] pkpass = createPkpassZip(passJsonString, manifestJsonString, signature);
        logger.info("Pass generated successfully (total size: {} bytes)", pkpass.length);

        return new PassGenerationResult(pkpass, serialNumber);
    }

    /**
     * Get static pass request based on type (simulates database/template lookup)
     */
    private com.example.passkit.dto.PassRequest getStaticPassRequest(String type) {
        com.example.passkit.dto.PassRequest request = new com.example.passkit.dto.PassRequest();

        switch (type.toUpperCase()) {
            case "BP":
            case "BOARDING":
            case "BOARDING_PASS":
                request.setType(com.example.passkit.dto.PassRequest.PassType.BOARDING_PASS);
                request.setDescription("Flight to NYC");
                request.setBackgroundColor("rgb(0, 51, 102)");
                request.setForegroundColor("rgb(255, 255, 255)");
                request.setTransitType("PKTransitTypeAir");
                request.setBarcodeMessage("BOARDING123456");
                request.setBarcodeFormat("PKBarcodeFormatQR");

                request.setPrimaryFields(Arrays.asList(
                        createField("origin", "SAN FRANCISCO", "SFO"),
                        createField("destination", "NEW YORK", "JFK")));
                request.setSecondaryFields(Arrays.asList(
                        createField("passenger", "PASSENGER", "Jane Smith"),
                        createField("seat", "SEAT", "14B")));
                request.setAuxiliaryFields(Arrays.asList(
                        createField("gate", "GATE", "A23"),
                        createField("boarding", "BOARDING", "2:45 PM")));
                break;

            case "CP":
            case "COUPON":
                request.setType(com.example.passkit.dto.PassRequest.PassType.COUPON);
                request.setDescription("Store Discount");
                request.setBackgroundColor("rgb(255, 87, 34)");
                request.setForegroundColor("rgb(255, 255, 255)");
                request.setBarcodeMessage("COUPON25OFF");
                request.setBarcodeFormat("PKBarcodeFormatQR"); // Assuming QR

                request.setPrimaryFields(Arrays.asList(
                        createField("offer", "", "25% OFF")));
                request.setSecondaryFields(Arrays.asList(
                        createField("expires", "EXPIRES", "Dec 31, 2026")));
                request.setBackFields(Arrays.asList(
                        createField("terms", "Terms", "Valid on purchases over $50.")));
                break;

            case "EP":
            case "EVENT":
            case "EVENT_TICKET":
                request.setType(com.example.passkit.dto.PassRequest.PassType.EVENT_TICKET);
                request.setDescription("Concert Ticket");
                request.setBackgroundColor("rgb(138, 43, 226)");
                request.setForegroundColor("rgb(255, 255, 255)");
                request.setBarcodeMessage("TICKET789012");
                request.setBarcodeFormat("PKBarcodeFormatQR");

                request.setPrimaryFields(Arrays.asList(
                        createField("event", "EVENT", "Rock Concert 2026")));
                request.setSecondaryFields(Arrays.asList(
                        createField("date", "DATE", "March 15, 2026"),
                        createField("time", "TIME", "8:00 PM")));
                request.setAuxiliaryFields(Arrays.asList(
                        createField("section", "SECTION", "VIP"),
                        createField("seat", "SEAT", "A-12")));
                break;

            case "SP":
            case "STORE":
            case "STORE_CARD":
                request.setType(com.example.passkit.dto.PassRequest.PassType.STORE_CARD);
                request.setDescription("Loyalty Card");
                request.setBackgroundColor("rgb(76, 175, 80)");
                request.setForegroundColor("rgb(255, 255, 255)");
                request.setBarcodeMessage("MEMBER345678");
                request.setBarcodeFormat("PKBarcodeFormatQR");

                request.setPrimaryFields(Arrays.asList(
                        createField("balance", "POINTS", "2,500")));
                request.setSecondaryFields(Arrays.asList(
                        createField("member", "MEMBER", "Alice Johnson")));
                request.setAuxiliaryFields(Arrays.asList(
                        createField("tier", "TIER", "Gold")));
                break;

            case "GP":
            case "GENERIC":
            default:
                request.setType(com.example.passkit.dto.PassRequest.PassType.GENERIC);
                request.setBackgroundColor("rgb(220, 20, 60)");
                request.setForegroundColor("rgb(255, 255, 255)");
                request.setLabelColor("rgb(255, 215, 0)");

                request.setPrimaryFields(Arrays.asList(
                        createField("title", "VIP Pass", "Gold Member")));
                request.setSecondaryFields(Arrays.asList(
                        createField("name", "Name", "John Doe")));
                break;
        }
        return request;
    }

    private com.example.passkit.dto.PassField createField(String key, String label, String value) {
        com.example.passkit.dto.PassField field = new com.example.passkit.dto.PassField();
        field.setKey(key);
        field.setLabel(label);
        field.setValue(value);
        return field;
    }

    private void savePassMetadata(String serialNumber, String passJsonString) {
        Optional<PassMetadata> existingMetadata = passMetadataRepository.findBySerialNumber(serialNumber);
        PassMetadata metadata;

        if (existingMetadata.isPresent()) {
            // Existing pass - increment version
            metadata = existingMetadata.get();
            metadata.setPassData(passJsonString);
            metadata.incrementVersion();
        } else {
            // New pass
            metadata = new PassMetadata(serialNumber, passTypeIdentifier);
            metadata.setPassData(passJsonString);
        }

        passMetadataRepository.save(metadata);
    }

    private String generate5DigitSerialNumber() {
        Random random = new Random();
        String serialNumber;
        do {
            serialNumber = String.format("%05d", random.nextInt(100000));
        } while (passMetadataRepository.existsBySerialNumber(serialNumber));
        return serialNumber;
    }

    public PassGenerationResult getUpdatedPass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        if (metadata.getStatus() == PassMetadata.PassStatus.REVOKED) {
            throw new Exception("Pass is revoked: " + metadata.getStatus());
        }

        String passJsonString = metadata.getPassData();

        // Create manifest and sign based on STORED data
        Map<String, String> manifest = createManifest(passJsonString);
        String manifestJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(manifest);
        byte[] signature = signManifest(manifestJsonString.getBytes(StandardCharsets.UTF_8));
        byte[] pkpass = createPkpassZip(passJsonString, manifestJsonString, signature);

        return new PassGenerationResult(pkpass, serialNumber);
    }

    public void updatePass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        // Increment version
        metadata.incrementVersion();
        passMetadataRepository.save(metadata);

        // Notify registered devices
        apnsService.notifyPassUpdate(passTypeIdentifier, serialNumber);
    }

    private String detectTypeFromPassJson(String json) {
        if (json == null)
            return "GENERIC";
        if (json.contains("\"boardingPass\""))
            return "BOARDING";
        if (json.contains("\"coupon\""))
            return "COUPON";
        if (json.contains("\"eventTicket\""))
            return "EVENT";
        if (json.contains("\"storeCard\""))
            return "STORE";
        return "GENERIC";
    }

    /**
     * Revoke a pass (soft delete)
     */
    public void revokePass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        // Set status to REVOKED
        metadata.setStatus(PassMetadata.PassStatus.REVOKED);
        metadata.setRevokedAt(java.time.LocalDateTime.now());
        metadata.incrementVersion();
        passMetadataRepository.save(metadata);

        logger.info("Pass revoked: {}", serialNumber);

        // Notify registered devices about the revocation
        apnsService.notifyPassUpdate(passTypeIdentifier, serialNumber);
    }

    /**
     * Expire a pass
     */
    public void expirePass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        // Set status to EXPIRED
        metadata.setStatus(PassMetadata.PassStatus.EXPIRED);
        metadata.setExpiresAt(java.time.LocalDateTime.now());
        metadata.incrementVersion();
        passMetadataRepository.save(metadata);

        logger.info("Pass expired: {}", serialNumber);

        // Notify registered devices about the expiration
        apnsService.notifyPassUpdate(passTypeIdentifier, serialNumber);
    }

    /**
     * Create pass.json structure based on request configuration
     */
    private Map<String, Object> createPassJson(String serialNumber, com.example.passkit.dto.PassRequest request) {
        Map<String, Object> pass = new HashMap<>();

        // Standard identifiers
        pass.put("formatVersion", 1);
        pass.put("passTypeIdentifier", passTypeIdentifier);
        pass.put("serialNumber", serialNumber);
        pass.put("teamIdentifier", teamIdentifier);

        // Organization name - use from request or default
        String orgName = (request != null && request.getOrganizationName() != null)
                ? request.getOrganizationName()
                : organizationName;
        pass.put("organizationName", orgName);

        // Description - use from request or default
        String desc = (request != null && request.getDescription() != null)
                ? request.getDescription()
                : "Example Pass";
        pass.put("description", desc);

        // Add web service configuration if available
        if (webServiceURL != null && !webServiceURL.isEmpty()) {
            pass.put("webServiceURL", webServiceURL);
            pass.put("authenticationToken", authenticationToken);
        }

        // Barcode configuration
        Map<String, Object> barcode = new HashMap<>();
        String barcodeMsg = (request != null && request.getBarcodeMessage() != null)
                ? request.getBarcodeMessage()
                : "123456789";
        String barcodeFormat = (request != null && request.getBarcodeFormat() != null)
                ? request.getBarcodeFormat()
                : "PKBarcodeFormatQR";
        barcode.put("message", barcodeMsg);
        barcode.put("format", barcodeFormat);
        barcode.put("messageEncoding", "iso-8859-1");
        pass.put("barcodes", Collections.singletonList(barcode));

        // Colors - use from request or defaults
        String bgColor = (request != null && request.getBackgroundColor() != null)
                ? request.getBackgroundColor()
                : "rgb(60, 65, 76)";
        String fgColor = (request != null && request.getForegroundColor() != null)
                ? request.getForegroundColor()
                : "rgb(255, 255, 255)";
        String lblColor = (request != null && request.getLabelColor() != null)
                ? request.getLabelColor()
                : "rgb(255, 255, 255)";

        pass.put("backgroundColor", bgColor);
        pass.put("foregroundColor", fgColor);
        pass.put("labelColor", lblColor);

        // Expiration date if provided
        if (request != null && request.getExpirationDate() != null) {
            pass.put("expirationDate", request.getExpirationDate().toString());
        }

        // Relevant date if provided
        if (request != null && request.getRelevantDate() != null) {
            pass.put("relevantDate", request.getRelevantDate().toString());
        }

        // Locations if provided
        if (request != null && request.getLocations() != null && !request.getLocations().isEmpty()) {
            pass.put("locations", request.getLocations());
        }

        // Add Serial Number and Status to Auxiliary Fields for FRONT FACE visibility
        if (request != null) {
            List<com.example.passkit.dto.PassField> auxFields = new ArrayList<>();
            if (request.getAuxiliaryFields() != null) {
                auxFields.addAll(request.getAuxiliaryFields());
            }
            // Add as first field or append? Appending is safer for layout.
            auxFields.add(createField("serialNumber", "Serial Number", serialNumber));
            auxFields.add(createField("status", "Status", "ACTIVE"));
            request.setAuxiliaryFields(auxFields);
        }

        // Determine pass type and create appropriate structure
        com.example.passkit.dto.PassRequest.PassType passType = (request != null && request.getType() != null)
                ? request.getType()
                : com.example.passkit.dto.PassRequest.PassType.GENERIC;

        switch (passType) {
            case BOARDING_PASS:

                pass.put("boardingPass", createBoardingPassStructure(request));
                break;
            case COUPON:
                pass.put("coupon", createCouponStructure(request));
                break;
            case EVENT_TICKET:
                pass.put("eventTicket", createEventTicketStructure(request));
                break;
            case STORE_CARD:
                pass.put("storeCard", createStoreCardStructure(request));
                break;
            case GENERIC:
            default:
                pass.put("generic", createGenericStructure(request));
                break;
        }

        return pass;
    }

    /**
     * Create generic pass structure
     */
    private Map<String, Object> createGenericStructure(com.example.passkit.dto.PassRequest request) {
        Map<String, Object> generic = new HashMap<>();

        if (request != null && request.getPrimaryFields() != null && !request.getPrimaryFields().isEmpty()) {
            generic.put("primaryFields", convertFields(request.getPrimaryFields()));
        } else {
            Map<String, Object> primaryField = new HashMap<>();
            primaryField.put("key", "title");
            primaryField.put("label", "Pass Title");
            primaryField.put("value", "Sample Pass");
            generic.put("primaryFields", Collections.singletonList(primaryField));
        }

        if (request != null && request.getSecondaryFields() != null && !request.getSecondaryFields().isEmpty()) {
            generic.put("secondaryFields", convertFields(request.getSecondaryFields()));
        } else {
            Map<String, Object> secondaryField = new HashMap<>();
            secondaryField.put("key", "subtitle");
            secondaryField.put("label", "Subtitle");
            secondaryField.put("value", "PassKit POC");
            generic.put("secondaryFields", Collections.singletonList(secondaryField));
        }

        if (request != null && request.getAuxiliaryFields() != null && !request.getAuxiliaryFields().isEmpty()) {
            generic.put("auxiliaryFields", convertFields(request.getAuxiliaryFields()));
        } else {
            Map<String, Object> auxField = new HashMap<>();
            auxField.put("key", "info");
            auxField.put("label", "Information");
            auxField.put("value", "iOS + Spring Boot");
            generic.put("auxiliaryFields", Collections.singletonList(auxField));
        }

        if (request != null && request.getBackFields() != null && !request.getBackFields().isEmpty()) {
            generic.put("backFields", convertFields(request.getBackFields()));
        } else {
            Map<String, Object> backField = new HashMap<>();
            backField.put("key", "details");
            backField.put("label", "Details");
            backField.put("value", "This is a sample pass generated by Spring Boot backend for Apple Wallet.");
            generic.put("backFields", Collections.singletonList(backField));
        }

        return generic;
    }

    /**
     * Create boarding pass structure
     */
    private Map<String, Object> createBoardingPassStructure(com.example.passkit.dto.PassRequest request) {
        Map<String, Object> boardingPass = new HashMap<>();

        // Transit type is required for boarding passes
        String transitType = (request != null && request.getTransitType() != null)
                ? request.getTransitType()
                : "PKTransitTypeAir";
        boardingPass.put("transitType", transitType);

        // Primary fields (origin/destination)
        if (request != null && request.getPrimaryFields() != null && !request.getPrimaryFields().isEmpty()) {
            boardingPass.put("primaryFields", convertFields(request.getPrimaryFields()));
        } else {
            List<Map<String, Object>> primaryFields = new ArrayList<>();
            primaryFields.add(createFieldMap("origin", "ORIGIN", "SFO"));
            primaryFields.add(createFieldMap("destination", "DESTINATION", "JFK"));
            boardingPass.put("primaryFields", primaryFields);
        }

        // Secondary fields
        if (request != null && request.getSecondaryFields() != null && !request.getSecondaryFields().isEmpty()) {
            boardingPass.put("secondaryFields", convertFields(request.getSecondaryFields()));
        } else {
            List<Map<String, Object>> secondaryFields = new ArrayList<>();
            secondaryFields.add(createFieldMap("passenger", "PASSENGER", "John Doe"));
            secondaryFields.add(createFieldMap("seat", "SEAT", "12A"));
            boardingPass.put("secondaryFields", secondaryFields);
        }

        // Auxiliary fields
        if (request != null && request.getAuxiliaryFields() != null && !request.getAuxiliaryFields().isEmpty()) {
            boardingPass.put("auxiliaryFields", convertFields(request.getAuxiliaryFields()));
        } else {
            List<Map<String, Object>> auxiliaryFields = new ArrayList<>();
            auxiliaryFields.add(createFieldMap("gate", "GATE", "B12"));
            auxiliaryFields.add(createFieldMap("boarding", "BOARDING", "10:30 AM"));
            boardingPass.put("auxiliaryFields", auxiliaryFields);
        }

        // Back fields
        if (request != null && request.getBackFields() != null && !request.getBackFields().isEmpty()) {
            boardingPass.put("backFields", convertFields(request.getBackFields()));
        }

        return boardingPass;
    }

    /**
     * Create coupon structure
     */
    private Map<String, Object> createCouponStructure(com.example.passkit.dto.PassRequest request) {
        Map<String, Object> coupon = new HashMap<>();

        // Primary fields (offer)
        if (request != null && request.getPrimaryFields() != null && !request.getPrimaryFields().isEmpty()) {
            coupon.put("primaryFields", convertFields(request.getPrimaryFields()));
        } else {
            Map<String, Object> primaryField = new HashMap<>();
            primaryField.put("key", "offer");
            primaryField.put("label", "");
            primaryField.put("value", "50% OFF");
            coupon.put("primaryFields", Collections.singletonList(primaryField));
        }

        // Secondary fields
        if (request != null && request.getSecondaryFields() != null && !request.getSecondaryFields().isEmpty()) {
            coupon.put("secondaryFields", convertFields(request.getSecondaryFields()));
        }

        // Auxiliary fields
        if (request != null && request.getAuxiliaryFields() != null && !request.getAuxiliaryFields().isEmpty()) {
            coupon.put("auxiliaryFields", convertFields(request.getAuxiliaryFields()));
        }

        // Back fields
        if (request != null && request.getBackFields() != null && !request.getBackFields().isEmpty()) {
            coupon.put("backFields", convertFields(request.getBackFields()));
        } else {
            Map<String, Object> backField = new HashMap<>();
            backField.put("key", "terms");
            backField.put("label", "Terms and Conditions");
            backField.put("value", "Valid for 30 days. Cannot be combined with other offers.");
            coupon.put("backFields", Collections.singletonList(backField));
        }

        return coupon;
    }

    /**
     * Create event ticket structure
     */
    private Map<String, Object> createEventTicketStructure(com.example.passkit.dto.PassRequest request) {
        Map<String, Object> eventTicket = new HashMap<>();

        // Primary fields (event name)
        if (request != null && request.getPrimaryFields() != null && !request.getPrimaryFields().isEmpty()) {
            eventTicket.put("primaryFields", convertFields(request.getPrimaryFields()));
        } else {
            Map<String, Object> primaryField = new HashMap<>();
            primaryField.put("key", "event");
            primaryField.put("label", "EVENT");
            primaryField.put("value", "Concert");
            eventTicket.put("primaryFields", Collections.singletonList(primaryField));
        }

        // Secondary fields (date/time)
        if (request != null && request.getSecondaryFields() != null && !request.getSecondaryFields().isEmpty()) {
            eventTicket.put("secondaryFields", convertFields(request.getSecondaryFields()));
        } else {
            List<Map<String, Object>> secondaryFields = new ArrayList<>();
            secondaryFields.add(createFieldMap("date", "DATE", "Jan 15, 2026"));
            secondaryFields.add(createFieldMap("time", "TIME", "7:00 PM"));
            eventTicket.put("secondaryFields", secondaryFields);
        }

        // Auxiliary fields (seat/section)
        if (request != null && request.getAuxiliaryFields() != null && !request.getAuxiliaryFields().isEmpty()) {
            eventTicket.put("auxiliaryFields", convertFields(request.getAuxiliaryFields()));
        } else {
            List<Map<String, Object>> auxiliaryFields = new ArrayList<>();
            auxiliaryFields.add(createFieldMap("section", "SECTION", "A"));
            auxiliaryFields.add(createFieldMap("seat", "SEAT", "12"));
            eventTicket.put("auxiliaryFields", auxiliaryFields);
        }

        // Back fields
        if (request != null && request.getBackFields() != null && !request.getBackFields().isEmpty()) {
            eventTicket.put("backFields", convertFields(request.getBackFields()));
        }

        return eventTicket;
    }

    /**
     * Create store card structure
     */
    private Map<String, Object> createStoreCardStructure(com.example.passkit.dto.PassRequest request) {
        Map<String, Object> storeCard = new HashMap<>();

        // Primary fields (balance/points)
        if (request != null && request.getPrimaryFields() != null && !request.getPrimaryFields().isEmpty()) {
            storeCard.put("primaryFields", convertFields(request.getPrimaryFields()));
        } else {
            Map<String, Object> primaryField = new HashMap<>();
            primaryField.put("key", "balance");
            primaryField.put("label", "BALANCE");
            primaryField.put("value", "$100.00");
            storeCard.put("primaryFields", Collections.singletonList(primaryField));
        }

        // Secondary fields
        if (request != null && request.getSecondaryFields() != null && !request.getSecondaryFields().isEmpty()) {
            storeCard.put("secondaryFields", convertFields(request.getSecondaryFields()));
        } else {
            Map<String, Object> secondaryField = new HashMap<>();
            secondaryField.put("key", "member");
            secondaryField.put("label", "MEMBER");
            secondaryField.put("value", "John Doe");
            storeCard.put("secondaryFields", Collections.singletonList(secondaryField));
        }

        // Auxiliary fields
        if (request != null && request.getAuxiliaryFields() != null && !request.getAuxiliaryFields().isEmpty()) {
            storeCard.put("auxiliaryFields", convertFields(request.getAuxiliaryFields()));
        }

        // Back fields
        if (request != null && request.getBackFields() != null && !request.getBackFields().isEmpty()) {
            storeCard.put("backFields", convertFields(request.getBackFields()));
        }

        return storeCard;
    }

    /**
     * Convert PassField DTOs to Map format for JSON
     */
    private List<Map<String, Object>> convertFields(List<com.example.passkit.dto.PassField> fields) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (com.example.passkit.dto.PassField field : fields) {
            Map<String, Object> fieldMap = new HashMap<>();
            fieldMap.put("key", field.getKey());
            if (field.getLabel() != null) {
                fieldMap.put("label", field.getLabel());
            }
            fieldMap.put("value", field.getValue());
            if (field.getTextAlignment() != null) {
                fieldMap.put("textAlignment", field.getTextAlignment());
            }
            if (field.getChangeMessage() != null) {
                fieldMap.put("changeMessage", field.getChangeMessage());
            }
            result.add(fieldMap);
        }
        return result;
    }

    /**
     * Helper method to create a field map
     */
    private Map<String, Object> createFieldMap(String key, String label, String value) {
        Map<String, Object> field = new HashMap<>();
        field.put("key", key);
        field.put("label", label);
        field.put("value", value);
        return field;
    }

    private Map<String, String> createManifest(String passJsonString) throws Exception {
        Map<String, String> manifest = new HashMap<>();

        // Hash pass.json
        String passHash = sha1Hash(passJsonString.getBytes(StandardCharsets.UTF_8));
        manifest.put("pass.json", passHash);

        // Hash PNG files if they exist
        try {
            byte[] iconPng = readResource("passkit/icon.png");
            manifest.put("icon.png", sha1Hash(iconPng));
            logger.debug("Added icon.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon.png to manifest: {}", e.getMessage());
        }

        try {
            byte[] icon2xPng = readResource("passkit/icon@2x.png");
            manifest.put("icon@2x.png", sha1Hash(icon2xPng));
            logger.debug("Added icon@2x.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon@2x.png to manifest: {}", e.getMessage());
        }

        try {
            byte[] icon3xPng = readResource("passkit/icon@3x.png");
            manifest.put("icon@3x.png", sha1Hash(icon3xPng));
            logger.debug("Added icon@3x.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon@3x.png to manifest: {}", e.getMessage());
        }

        return manifest;
    }

    private String sha1Hash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private byte[] signManifest(byte[] manifestData) throws Exception {
        // Load certificates if not already loaded
        if (privateKey == null || passCertificate == null || wwdrCertificate == null) {
            loadCertificates();
        }

        // Create CMS signed data
        CMSTypedData cmsData = new CMSProcessableByteArray(manifestData);

        // Certificate chain order: Pass Type ID certificate first, then WWDR
        // certificate
        // This order is important for proper chain validation
        @SuppressWarnings("unchecked")
        Store<X509Certificate> certStore = new JcaCertStore(Arrays.asList(passCertificate, wwdrCertificate));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC")
                .build();

        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digestProvider)
                        .build(signer, passCertificate));

        generator.addCertificates(certStore);

        CMSSignedData signedData = generator.generate(cmsData, false);

        return signedData.getEncoded();
    }

    private void loadCertificates() throws Exception {
        try {
            // Load private key - try multiple path locations
            String resolvedPrivateKeyPath = resolveCertificatePath(privateKeyPath, "private key");
            logger.info("Loading private key from: {}", resolvedPrivateKeyPath);

            try (PEMParser pemParser = new PEMParser(new FileReader(resolvedPrivateKeyPath))) {
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                if (object instanceof PrivateKeyInfo) {
                    privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                    logger.info("Successfully loaded private key");
                } else {
                    throw new Exception("Private key file does not contain a valid private key");
                }
            }

            // Load pass certificate - try multiple path locations
            String resolvedCertPath = resolveCertificatePath(certificatePath, "pass certificate");
            logger.info("Loading pass certificate from: {}", resolvedCertPath);

            try (FileInputStream fis = new FileInputStream(resolvedCertPath)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                passCertificate = (X509Certificate) cf.generateCertificate(fis);
                String certSubject = passCertificate.getSubjectX500Principal().toString();
                logger.info("Successfully loaded pass certificate. Subject: {}", certSubject);
            }

            // Load WWDR certificate - try multiple path locations
            String resolvedWwdrPath = resolveCertificatePath(wwdrPath, "WWDR certificate");
            logger.info("Loading WWDR certificate from: {}", resolvedWwdrPath);

            try (FileInputStream fis = new FileInputStream(resolvedWwdrPath)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                wwdrCertificate = (X509Certificate) cf.generateCertificate(fis);
                String wwdrSubject = wwdrCertificate.getSubjectX500Principal().toString();
                logger.info("Successfully loaded WWDR certificate. Subject: {}", wwdrSubject);
            }

            // Verify certificates are valid
            verifyCertificates();

            // Verify private key matches certificate
            verifyPrivateKeyMatchesCertificate();

        } catch (Exception e) {
            logger.error("Failed to load certificates: {}", e.getMessage(), e);
            throw new Exception(
                    "Failed to load certificates. Please ensure all certificate files are present and valid. " +
                            "Error: " + e.getMessage() +
                            ". Checked paths: privateKey=" + privateKeyPath +
                            ", certificate=" + certificatePath +
                            ", wwdr=" + wwdrPath,
                    e);
        }
    }

    private void verifyPrivateKeyMatchesCertificate() throws Exception {
        if (privateKey == null || passCertificate == null) {
            return;
        }

        try {
            // Try to create a signature with the private key and verify with the
            // certificate's public key
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] testData = "test".getBytes();
            signature.update(testData);
            byte[] sigBytes = signature.sign();

            signature.initVerify(passCertificate.getPublicKey());
            signature.update(testData);
            boolean verified = signature.verify(sigBytes);

            if (verified) {
                logger.info("Private key matches the pass certificate");
            } else {
                throw new Exception("Private key does not match the pass certificate");
            }
        } catch (Exception e) {
            logger.error("Failed to verify private key matches certificate: {}", e.getMessage());
            throw new Exception(
                    "Private key verification failed. The private key may not match the certificate: " + e.getMessage(),
                    e);
        }
    }

    private String resolveCertificatePath(String configuredPath, String certificateType) throws FileNotFoundException {
        // Try the configured path as-is (could be absolute or relative)
        java.nio.file.Path path = Paths.get(configuredPath);
        if (Files.exists(path) && Files.isRegularFile(path)) {
            return path.toAbsolutePath().toString();
        }

        // Try relative to project root (when running from project root)
        String[] alternativePaths = {
                configuredPath, // Original path
                "../" + configuredPath, // If running from backend directory
                "../../" + configuredPath, // If running from backend/target directory
                "certs/" + new java.io.File(configuredPath).getName(), // Try root certs folder
                "../certs/" + new java.io.File(configuredPath).getName() // Try root certs from backend
        };

        for (String altPath : alternativePaths) {
            path = Paths.get(altPath);
            if (Files.exists(path) && Files.isRegularFile(path)) {
                logger.debug("Found {} at alternative path: {}", certificateType, path.toAbsolutePath());
                return path.toAbsolutePath().toString();
            }
        }

        // If still not found, provide helpful error message
        StringBuilder errorMsg = new StringBuilder();
        errorMsg.append(certificateType).append(" not found at: ").append(configuredPath);
        errorMsg.append("\nTried paths:");
        for (String altPath : alternativePaths) {
            errorMsg.append("\n  - ").append(Paths.get(altPath).toAbsolutePath());
        }
        errorMsg.append("\nCurrent working directory: ").append(System.getProperty("user.dir"));

        throw new FileNotFoundException(errorMsg.toString());
    }

    private void verifyCertificates() throws Exception {
        // Verify passTypeIdentifier matches certificate
        if (passCertificate != null) {
            String certSubject = passCertificate.getSubjectX500Principal().toString();
            logger.info("Verifying certificate matches passTypeIdentifier: {}", passTypeIdentifier);
            logger.info("Certificate subject: {}", certSubject);

            // Check if this is a test certificate
            boolean isTestCertificate = certSubject.contains("Test Certificate") ||
                    certSubject.contains("Test Organization") ||
                    certSubject.contains("test");

            if (isTestCertificate) {
                logger.error(
                        "WARNING: This appears to be a TEST certificate, not a real Apple Pass Type ID certificate!");
                logger.error("Test certificates will NOT work with Apple Wallet.");
                logger.error("You need a real Pass Type ID certificate from Apple Developer Portal.");
                logger.error("Certificate subject: {}", certSubject);
                logger.error("Expected CN should contain: {}", passTypeIdentifier);
                logger.error("Expected OU should be: {}", teamIdentifier);
                throw new Exception(
                        "Test certificate detected. Apple Wallet requires a real Pass Type ID certificate from Apple Developer Portal. "
                                +
                                "The certificate subject '" + certSubject + "' does not match the required format. " +
                                "Please obtain a real Pass Type ID certificate from https://developer.apple.com/account/resources/identifiers/list/passTypeId");
            }

            // Extract certificate details
            String cn = null;
            String ou = null;
            String[] subjectParts = certSubject.split(",");
            for (String part : subjectParts) {
                part = part.trim();
                if (part.startsWith("CN=")) {
                    cn = part.substring(3);
                    logger.info("Certificate Common Name (CN): {}", cn);
                    // The CN should match or contain the passTypeIdentifier
                    if (!cn.equals(passTypeIdentifier) && !cn.contains(passTypeIdentifier)
                            && !passTypeIdentifier.contains(cn)) {
                        logger.warn("Certificate CN '{}' does not match passTypeIdentifier '{}'", cn,
                                passTypeIdentifier);
                        logger.warn("This may cause Apple Wallet to reject the pass");
                    } else {
                        logger.info("✓ Certificate CN matches passTypeIdentifier");
                    }
                } else if (part.startsWith("OU=")) {
                    ou = part.substring(3);
                    logger.info("Certificate Organizational Unit (OU): {}", ou);
                    // The OU should match the teamIdentifier
                    if (ou.equals(teamIdentifier)) {
                        logger.info("✓ Team identifier matches certificate OU");
                    } else {
                        logger.warn("Team identifier '{}' does not match certificate OU '{}'", teamIdentifier, ou);
                        logger.warn("This may cause Apple Wallet to reject the pass");
                    }
                }
            }

            if (cn == null) {
                logger.warn("Certificate does not have a CN (Common Name) field");
            }
            if (ou == null) {
                logger.warn(
                        "Certificate does not have an OU (Organizational Unit) field - this is required for teamIdentifier");
            }

            // Verify certificate is not expired
            try {
                passCertificate.checkValidity();
                logger.info("✓ Pass certificate is valid (not expired)");
            } catch (Exception e) {
                logger.error("Pass certificate validation failed: {}", e.getMessage());
                throw new Exception("Pass certificate is expired or invalid: " + e.getMessage(), e);
            }
        }

        // Verify WWDR certificate
        if (wwdrCertificate != null) {
            String wwdrSubject = wwdrCertificate.getSubjectX500Principal().toString();
            logger.info("WWDR certificate subject: {}", wwdrSubject);

            // Verify WWDR certificate is from Apple
            if (!wwdrSubject.contains("Apple") && !wwdrSubject.contains("Worldwide Developer Relations")) {
                logger.warn("  WWDR certificate may not be the official Apple WWDR certificate");
            } else {
                logger.info("  WWDR certificate appears to be from Apple");
            }

            try {
                wwdrCertificate.checkValidity();
                logger.info("✓ WWDR certificate is valid (not expired)");
            } catch (Exception e) {
                logger.error("WWDR certificate validation failed: {}", e.getMessage());
                throw new Exception("WWDR certificate is expired or invalid: " + e.getMessage(), e);
            }
        }
    }

    private byte[] createPkpassZip(String passJsonString, String manifestJsonString, byte[] signature)
            throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            // Add pass.json
            ZipEntry passEntry = new ZipEntry("pass.json");
            zos.putNextEntry(passEntry);
            zos.write(passJsonString.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Add manifest.json
            ZipEntry manifestEntry = new ZipEntry("manifest.json");
            zos.putNextEntry(manifestEntry);
            zos.write(manifestJsonString.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Add signature
            ZipEntry signatureEntry = new ZipEntry("signature");
            zos.putNextEntry(signatureEntry);
            zos.write(signature);
            zos.closeEntry();

            // add png files
            try {
                byte[] iconPng = readResource("passkit/icon.png");
                ZipEntry pngLogo = new ZipEntry("icon.png");
                zos.putNextEntry(pngLogo);
                zos.write(iconPng);
                zos.closeEntry();
                logger.info("Successfully added icon.png to pass ({} bytes)", iconPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon.png: {}", e.getMessage(), e);
            }

            try {
                byte[] icon2xPng = readResource("passkit/icon@2x.png");
                ZipEntry pngLogo2 = new ZipEntry("icon@2x.png");
                zos.putNextEntry(pngLogo2);
                zos.write(icon2xPng);
                zos.closeEntry();
                logger.info("Successfully added icon@2x.png to pass ({} bytes)", icon2xPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon@2x.png: {}", e.getMessage(), e);
            }

            try {
                byte[] icon3xPng = readResource("passkit/icon@3x.png");
                ZipEntry pngLogo3 = new ZipEntry("icon@3x.png");
                zos.putNextEntry(pngLogo3);
                zos.write(icon3xPng);
                zos.closeEntry();
                logger.info("Successfully added icon@3x.png to pass ({} bytes)", icon3xPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon@3x.png: {}", e.getMessage(), e);
            }
        }

        return baos.toByteArray();
    }

    private byte[] readResource(String path) throws IOException {
        ClassPathResource res = new ClassPathResource(path);
        if (!res.exists()) {
            throw new FileNotFoundException("Resource not found: " + path + " (checked classpath)");
        }
        try (InputStream in = res.getInputStream()) {
            byte[] data = in.readAllBytes();
            logger.debug("Loaded resource {}: {} bytes", path, data.length);
            return data;
        }
    }
}
