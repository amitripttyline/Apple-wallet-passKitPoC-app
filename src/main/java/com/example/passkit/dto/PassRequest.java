package com.example.passkit.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DTO for requesting pass generation with customization options.
 * Supports multiple pass types and custom fields.
 */
public class PassRequest {

    /**
     * Type of pass to generate
     */
    private PassType type = PassType.GENERIC;

    /**
     * Custom colors for the pass
     */
    private String backgroundColor;
    private String foregroundColor;
    private String labelColor;

    /**
     * Pass fields - flexible structure
     */
    private List<PassField> primaryFields;
    private List<PassField> secondaryFields;
    private List<PassField> auxiliaryFields;
    private List<PassField> backFields;

    /**
     * Barcode configuration
     */
    private String barcodeMessage;
    private String barcodeFormat = "PKBarcodeFormatQR"; // Default to QR code

    /**
     * Pass metadata
     */
    private String description;
    private String organizationName;
    private LocalDateTime expirationDate;

    /**
     * Boarding pass specific fields
     */
    private String transitType; // PKTransitTypeAir, PKTransitTypeTrain, etc.

    /**
     * Location-based features
     */
    private List<Map<String, Object>> locations;

    /**
     * Relevance configuration
     */
    private LocalDateTime relevantDate;

    // Constructors
    public PassRequest() {
    }

    // Getters and Setters
    public PassType getType() {
        return type;
    }

    public void setType(PassType type) {
        this.type = type;
    }

    public String getBackgroundColor() {
        return backgroundColor;
    }

    public void setBackgroundColor(String backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public String getForegroundColor() {
        return foregroundColor;
    }

    public void setForegroundColor(String foregroundColor) {
        this.foregroundColor = foregroundColor;
    }

    public String getLabelColor() {
        return labelColor;
    }

    public void setLabelColor(String labelColor) {
        this.labelColor = labelColor;
    }

    public List<PassField> getPrimaryFields() {
        return primaryFields;
    }

    public void setPrimaryFields(List<PassField> primaryFields) {
        this.primaryFields = primaryFields;
    }

    public List<PassField> getSecondaryFields() {
        return secondaryFields;
    }

    public void setSecondaryFields(List<PassField> secondaryFields) {
        this.secondaryFields = secondaryFields;
    }

    public List<PassField> getAuxiliaryFields() {
        return auxiliaryFields;
    }

    public void setAuxiliaryFields(List<PassField> auxiliaryFields) {
        this.auxiliaryFields = auxiliaryFields;
    }

    public List<PassField> getBackFields() {
        return backFields;
    }

    public void setBackFields(List<PassField> backFields) {
        this.backFields = backFields;
    }

    public String getBarcodeMessage() {
        return barcodeMessage;
    }

    public void setBarcodeMessage(String barcodeMessage) {
        this.barcodeMessage = barcodeMessage;
    }

    public String getBarcodeFormat() {
        return barcodeFormat;
    }

    public void setBarcodeFormat(String barcodeFormat) {
        this.barcodeFormat = barcodeFormat;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public LocalDateTime getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(LocalDateTime expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getTransitType() {
        return transitType;
    }

    public void setTransitType(String transitType) {
        this.transitType = transitType;
    }

    public List<Map<String, Object>> getLocations() {
        return locations;
    }

    public void setLocations(List<Map<String, Object>> locations) {
        this.locations = locations;
    }

    public LocalDateTime getRelevantDate() {
        return relevantDate;
    }

    public void setRelevantDate(LocalDateTime relevantDate) {
        this.relevantDate = relevantDate;
    }

    /**
     * Enum for supported pass types
     */
    public enum PassType {
        GENERIC,
        BOARDING_PASS,
        COUPON,
        EVENT_TICKET,
        STORE_CARD
    }
}
