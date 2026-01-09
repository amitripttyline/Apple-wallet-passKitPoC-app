package com.example.passkit.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "pass_metadata")
public class PassMetadata {

    @Id
    @Column(name = "serial_number", length = 100)
    private String serialNumber;

    @Column(name = "pass_type_id", nullable = false, length = 255)
    private String passTypeId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private PassStatus status;

    @Column(name = "version", nullable = false)
    private Integer version;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "pass_data", columnDefinition = "TEXT")
    private String passData; // JSON string of the pass

    // Constructors
    public PassMetadata() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        this.version = 1;
        this.status = PassStatus.ACTIVE;
    }

    public PassMetadata(String serialNumber, String passTypeId) {
        this();
        this.serialNumber = serialNumber;
        this.passTypeId = passTypeId;
    }

    // Getters and Setters
    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getPassTypeId() {
        return passTypeId;
    }

    public void setPassTypeId(String passTypeId) {
        this.passTypeId = passTypeId;
    }

    public PassStatus getStatus() {
        return status;
    }

    public void setStatus(PassStatus status) {
        this.status = status;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getPassData() {
        return passData;
    }

    public void setPassData(String passData) {
        this.passData = passData;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public void incrementVersion() {
        this.version++;
        this.updatedAt = LocalDateTime.now();
    }

    public enum PassStatus {
        ACTIVE,
        EXPIRED,
        REVOKED
    }
}
