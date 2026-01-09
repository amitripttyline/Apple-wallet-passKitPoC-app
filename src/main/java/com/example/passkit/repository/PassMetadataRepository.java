package com.example.passkit.repository;

import com.example.passkit.model.PassMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PassMetadataRepository extends JpaRepository<PassMetadata, String> {

    Optional<PassMetadata> findBySerialNumber(String serialNumber);

    boolean existsBySerialNumber(String serialNumber);
}
