// Package proto contains generated protobuf types for Signal's provisioning
// and WebSocket protocols.
package proto

//go:generate protoc --go_out=. --go_opt=paths=source_relative Provisioning.proto WebSocketResources.proto
