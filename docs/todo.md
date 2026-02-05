# Global todo

## Open Tasks

- [ ] **Task 07: Phone Number Send** - Support phone numbers as send recipients ([details](task07-phone-number-send.md))

## Investigations

- [ ] **Task 05: Session Decryption** - Debug session decryption failures ([details](task05-session-decryption-failure.md))
- [ ] **Task 10: iPhone Message Visibility** - Messages delivered but not visible on iPhone ([details](task10-iphone-message-visibility.md))

## Refactoring

- [ ] Make httpclient a property of signal client, so individual methods do not need to instantiate a new one
- [ ] Remove duplicate code, identify simplifications
- [ ] Simplify SendTextMessage gigantic signature
- [ ] logf > c.logf
- [ ] speed up tests
- [ ] un-wrap methods for sending and receiving and tie them to the service struct

## Completed

- [x] Task 01: CGO Bindings ([details](task01-cgo-bindings.md))
- [x] Task 02: Service Layer ([details](task02-service-layer.md))
- [x] Task 03: UUID to Tel Plan ([details](task03-uuid-to-tel-plan.md))
- [x] Task 04: Sealed Sender ([details](task04-sealed-sender.md))
- [x] Task 06: Primary Registration ([details](task06-primary-registration.md))
- [x] Task 08: Device Caching ([details](task08-device-caching.md))
- [x] Task 09: Message Padding ([details](task09-message-padding.md))
- [x] Task 11: libsignal v0.87.0 Upgrade ([details](task11-libsignal-v087-upgrade.md))
