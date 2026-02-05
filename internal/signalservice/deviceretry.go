package signalservice

import (
	"errors"
	"slices"
)

// initialDevices returns the starting device list for a recipient and the
// device ID to skip during 409 retry (0 for none). When sendingToSelf is
// true, the local device is filtered out and returned as skipDevice.
func (s *Service) initialDevices(recipient string, sendingToSelf bool) (deviceIDs []int, skipDevice int) {
	deviceIDs, _ = s.store.GetDevices(recipient)
	if len(deviceIDs) == 0 {
		deviceIDs = []int{1}
	}
	if sendingToSelf {
		deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == s.localDeviceID })
		skipDevice = s.localDeviceID
	}
	return deviceIDs, skipDevice
}

// withDeviceRetry runs tryFn with the given device list, retrying on 409/410
// errors from the Signal server. On 409 (device mismatch), it updates the
// device list and archives sessions. On 410 (stale sessions), it archives
// the stale sessions. skipDevice is a device ID to never add to the list
// (use 0 for none; use localDeviceID when sending to self).
func (s *Service) withDeviceRetry(recipient string, deviceIDs []int, skipDevice int, tryFn func([]int) error) error {
	const maxAttempts = 5
	for attempt := range maxAttempts {
		err := tryFn(deviceIDs)
		if err == nil {
			_ = s.store.SetDevices(recipient, deviceIDs)
			return nil
		}
		if attempt == maxAttempts-1 {
			return err
		}

		var staleErr *StaleDevicesError
		var mismatchErr *MismatchedDevicesError

		switch {
		case errors.As(err, &staleErr):
			logf(s.logger, "retry: 410 stale=%v", staleErr.StaleDevices)
			for _, deviceID := range staleErr.StaleDevices {
				_ = s.store.ArchiveSession(recipient, uint32(deviceID))
			}
		case errors.As(err, &mismatchErr):
			logf(s.logger, "retry: 409 missing=%v extra=%v devices=%v",
				mismatchErr.MissingDevices, mismatchErr.ExtraDevices, deviceIDs)
			// Archive all current sessions (local state advanced during Encrypt).
			for _, deviceID := range deviceIDs {
				_ = s.store.ArchiveSession(recipient, uint32(deviceID))
			}
			for _, deviceID := range mismatchErr.ExtraDevices {
				deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == deviceID })
			}
			for _, deviceID := range mismatchErr.MissingDevices {
				if deviceID != skipDevice && !slices.Contains(deviceIDs, deviceID) {
					deviceIDs = append(deviceIDs, deviceID)
				}
			}
			_ = s.store.SetDevices(recipient, deviceIDs)
		default:
			return err
		}
	}
	return nil
}
