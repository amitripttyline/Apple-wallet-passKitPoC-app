package com.example.passkit.service;

import com.example.passkit.model.DeviceRegistration;
import com.example.passkit.repository.DeviceRegistrationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class PassRegistrationService {

    private static final Logger logger = LoggerFactory.getLogger(PassRegistrationService.class);

    @Autowired
    private DeviceRegistrationRepository deviceRegistrationRepository;

    /**
     * Register a device for pass updates
     */
    @Transactional
    public DeviceRegistration registerDevice(String deviceId, String passTypeId, 
                                             String serialNumber, String pushToken) {
        logger.info("Registering device: deviceId={}, passTypeId={}, serialNumber={}", 
                    deviceId, passTypeId, serialNumber);

        Optional<DeviceRegistration> existing = deviceRegistrationRepository
                .findByDeviceIdAndPassTypeIdAndSerialNumber(deviceId, passTypeId, serialNumber);

        if (existing.isPresent()) {
            // Update push token if changed
            DeviceRegistration registration = existing.get();
            if (pushToken != null && !pushToken.equals(registration.getPushToken())) {
                registration.setPushToken(pushToken);
                registration = deviceRegistrationRepository.save(registration);
                logger.info("Updated push token for existing registration: id={}", registration.getId());
            } else {
                logger.info("Device already registered: id={}", registration.getId());
            }
            return registration;
        }

        DeviceRegistration registration = new DeviceRegistration(deviceId, passTypeId, serialNumber, pushToken);
        registration = deviceRegistrationRepository.save(registration);
        logger.info("Created new device registration: id={}", registration.getId());

        return registration;
    }

    /**
     * Unregister a device from pass updates
     */
    @Transactional
    public boolean unregisterDevice(String deviceId, String passTypeId, String serialNumber) {
        logger.info("Unregistering device: deviceId={}, passTypeId={}, serialNumber={}", 
                    deviceId, passTypeId, serialNumber);

        Optional<DeviceRegistration> registration = deviceRegistrationRepository
                .findByDeviceIdAndPassTypeIdAndSerialNumber(deviceId, passTypeId, serialNumber);

        if (registration.isPresent()) {
            deviceRegistrationRepository.delete(registration.get());
            logger.info("Device unregistered successfully");
            return true;
        }

        logger.warn("Device registration not found for unregistration");
        return false;
    }

    /**
     * Get all serial numbers for passes that a device is registered for
     */
    public List<String> getRegisteredSerialNumbers(String deviceId, String passTypeId) {
        logger.debug("Fetching registered serial numbers: deviceId={}, passTypeId={}", 
                     deviceId, passTypeId);

        List<DeviceRegistration> registrations = deviceRegistrationRepository
                .findByDeviceIdAndPassTypeId(deviceId, passTypeId);

        return registrations.stream()
                .map(DeviceRegistration::getSerialNumber)
                .toList();
    }

    /**
     * Get all devices registered for a specific pass
     */
    public List<DeviceRegistration> getDevicesForPass(String passTypeId, String serialNumber) {
        logger.debug("Fetching devices for pass: passTypeId={}, serialNumber={}", 
                     passTypeId, serialNumber);

        return deviceRegistrationRepository.findByPassTypeIdAndSerialNumber(passTypeId, serialNumber);
    }

    /**
     * Check if a device is registered for a pass
     */
    public boolean isDeviceRegistered(String deviceId, String passTypeId, String serialNumber) {
        return deviceRegistrationRepository
                .existsByDeviceIdAndPassTypeIdAndSerialNumber(deviceId, passTypeId, serialNumber);
    }
}
