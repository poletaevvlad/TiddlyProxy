.PHONY: make_directory build_plugin clean

all: make_directory build_plugin clean
	make clean

make_directory: clean
	mkdir build
	mkdir build/plugins
	mkdir build/plugins/poletaevvlad
	ln -s $(shell pwd)/plugin build/plugins/poletaevvlad/proxy-logout
	mkdir build/tiddlers
	echo -e "title: $$:/DefaultTiddlers\n\n$$:/plugins/poletaevvlad/proxy-logout" > build/tiddlers/DefaultTiddlers.tid
	echo -e "title: $$:/SiteTitle\n\n~TiddlyProxy" > build/tiddlers/SiteTitle.tid
	echo -e "title: $$:/SiteSubtitle\n\nA reverse proxy for ~TiddlyWiki " > build/tiddlers/SiteSubtitle.tid

build_plugin:
	cp ./tiddlywiki.info build/tiddlywiki.info
	export TIDDLYWIKI_PLUGIN_PATH=$(shell pwd)/build/plugins && \
	npx tiddlywiki build --build index
	cp build/output/index.html index.html

clean:
	rm -rf build
