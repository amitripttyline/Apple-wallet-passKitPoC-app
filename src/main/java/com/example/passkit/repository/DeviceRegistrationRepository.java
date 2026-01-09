package com.example.passkit.repository;

import com.example.passkit.model.DeviceRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DeviceRegistrationRepository extends JpaRepository<DeviceRegistration, Long> {

    Optional<DeviceRegistration> findByDeviceIdAndPassTypeIdAndSerialNumber(
            String deviceId, String passTypeId, String serialNumber);

    List<DeviceRegistration> findByDeviceIdAndPassTypeId(String deviceId, String passTypeId);

    List<DeviceRegistration> findByPassTypeIdAndSerialNumber(String passTypeId, String serialNumber);

    void deleteByDeviceIdAndPassTypeIdAndSerialNumber(
            String deviceId, String passTypeId, String serialNumber);

    boolean existsByDeviceIdAndPassTypeIdAndSerialNumber(
            String deviceId, String passTypeId, String serialNumber);
}
