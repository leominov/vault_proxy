.PHONY: test
test:
	@go test ./... -cover

.PHONY: test-report
test-report:
	@go test ./... -coverprofile=coverage.txt && go tool cover -html=coverage.txt
