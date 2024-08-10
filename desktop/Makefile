build-ui:
	$(MAKE) -C ../ui build
	rm -rf ./ui/
	cp -r ../ui/dist/ ./ui/

run: build-ui
	go run main.go

dev: build-ui
	XELA_DEV_MODE=1 go run main.go
