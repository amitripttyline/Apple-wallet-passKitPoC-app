package com.example.passkit.dto;

/**
 * DTO representing a field in an Apple Wallet pass.
 * Fields can be primary, secondary, auxiliary, or back fields.
 */
public class PassField {

    /**
     * Unique key for this field
     */
    private String key;

    /**
     * Label displayed above the value
     */
    private String label;

    /**
     * The actual value to display
     */
    private String value;

    /**
     * Optional text alignment (PKTextAlignmentLeft, PKTextAlignmentCenter,
     * PKTextAlignmentRight, PKTextAlignmentNatural)
     */
    private String textAlignment;

    /**
     * Optional change message for updates
     */
    private String changeMessage;

    // Constructors
    public PassField() {
    }

    public PassField(String key, String label, String value) {
        this.key = key;
        this.label = label;
        this.value = value;
    }

    // Getters and Setters
    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getTextAlignment() {
        return textAlignment;
    }

    public void setTextAlignment(String textAlignment) {
        this.textAlignment = textAlignment;
    }

    public String getChangeMessage() {
        return changeMessage;
    }

    public void setChangeMessage(String changeMessage) {
        this.changeMessage = changeMessage;
    }
}
