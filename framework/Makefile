
.DEFAULT_GOAL := all

deps:
	sudo apt-get install automake libtool python-pip python-dev libffi-dev libssl-dev libtiff5-dev libjpeg8-dev zlib1g-dev libwebp-dev libxml2-dev libxslt1-dev
	sudo pip install setuptools --upgrade
	sudo pip install psutil
	sudo pip install yara-python
	sudo pip install mitmproxy==0.18.3

reflash:
	cd ../reflash; rdmd build_reflash.d
	cd ../framework; ln -s ../reflash/reflash reflash
	chmod 755 proxy.py run_*.sh monitor replay

all: reflash

clean:
	rm -f ../reflash/reflash
	rm -f reflash
	rm -f *.pyc
	rm -rf dumps cadir

