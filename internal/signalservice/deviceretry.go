package signalservice

import (
	"errors"
	"slices"
)

// initialDevices returns the starting device list for a recipient and the
// device ID to skip during 409 retry (0 for none). When sendingToSelf is
// true, the local device is filtered out and returned as skipDevice.
func (snd *Sender) initialDevices(recipient string, sendingToSelf bool) (deviceIDs []int, skipDevice int) {
	deviceIDs, _ = snd.dataStore.GetDevices(recipient)
	if len(deviceIDs) == 0 {
		deviceIDs = []int{1}
	}
	if sendingToSelf {
		deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == snd.localDeviceID })
		skipDevice = snd.localDeviceID
	}
	return deviceIDs, skipDevice
}

const maxDeviceRetryAttempts = 5

// retryOnDeviceError runs tryFn up to maxDeviceRetryAttempts times.
// On each failure, handleErr is called to adjust state. If handleErr returns
// a non-nil error, the retry loop stops and returns that error.
func retryOnDeviceError(tryFn func() error, handleErr func(error) error) error {
	for attempt := range maxDeviceRetryAttempts {
		err := tryFn()
		if err == nil {
			return nil
		}
		if attempt == maxDeviceRetryAttempts-1 {
			return err
		}
		if herr := handleErr(err); herr != nil {
			return herr
		}
	}
	return nil
}

// withDeviceRetry runs tryFn with the given device list, retrying on 409/410
// errors from the Signal server. On 409 (device mismatch), it updates the
// device list and archives sessions. On 410 (stale sessions), it archives
// the stale sessions. skipDevice is a device ID to never add to the list
// (use 0 for none; use localDeviceID when sending to self).
func (snd *Sender) withDeviceRetry(recipient string, deviceIDs []int, skipDevice int, tryFn func([]int) error) error {
	return retryOnDeviceError(
		func() error {
			err := tryFn(deviceIDs)
			if err == nil {
				_ = snd.dataStore.SetDevices(recipient, deviceIDs)
			}
			return err
		},
		func(err error) error {
			var staleErr *staleDevicesError
			var mismatchErr *mismatchedDevicesError

			switch {
			case errors.As(err, &staleErr):
				logf(snd.logger, "retry: 410 stale=%v", staleErr.StaleDevices)
				for _, deviceID := range staleErr.StaleDevices {
					_ = snd.dataStore.ArchiveSession(recipient, uint32(deviceID))
				}
			case errors.As(err, &mismatchErr):
				logf(snd.logger, "retry: 409 missing=%v extra=%v devices=%v",
					mismatchErr.MissingDevices, mismatchErr.ExtraDevices, deviceIDs)
				for _, deviceID := range deviceIDs {
					_ = snd.dataStore.ArchiveSession(recipient, uint32(deviceID))
				}
				for _, deviceID := range mismatchErr.ExtraDevices {
					deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == deviceID })
				}
				for _, deviceID := range mismatchErr.MissingDevices {
					if deviceID != skipDevice && !slices.Contains(deviceIDs, deviceID) {
						deviceIDs = append(deviceIDs, deviceID)
					}
				}
				_ = snd.dataStore.SetDevices(recipient, deviceIDs)
			default:
				return err
			}
			return nil
		},
	)
}

