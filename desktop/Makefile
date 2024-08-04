run:
	$(MAKE) -C ../ui build
	rm -r ./ui/
	cp -r ../ui/dist/ ./ui/
	go run main.go