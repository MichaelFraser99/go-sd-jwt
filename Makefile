test:
	go test ./...

fuzz:
	@(cd ./kbjwt && make fuzz)
