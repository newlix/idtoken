token.pb.go: token.proto
	protoc --go_out=. token.proto