BUILD=build
INPUT_LIB=lib.js
OUTPUT_LIB=$(BUILD)/lib.js

HTML=$(BUILD)/tzlibre-signature-webtool.html
TMPL=tzlibre-signature-webtool.tmpl.html

IMAGE=tzlibre/browserify-sign-lib
CONTAINER=sign-container

all: docker-lib template

template:
	awk 'BEGIN{l="";while(( getline line<"$(OUTPUT_LIB)") > 0 ) {l=l"\n"line}}{if($$0~"#LIB")print l;else print}' $(TMPL) > $(HTML)

docker-lib: mkdir
	docker build -t $(IMAGE) .
	docker run --name=$(CONTAINER) $(IMAGE)
	docker cp $(CONTAINER):/tmp/build/lib.js $(OUTPUT_LIB)
	docker rm $(CONTAINER)

lib: mkdir
	browserify $(INPUT_LIB) -s generateData > $(OUTPUT_LIB)

mkdir: clean
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
