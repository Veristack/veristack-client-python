PASSWORD =

#: help - Display callable targets.
.PHONY: help
help:
	@echo "Reference card for usual actions in development environment."
	@echo "Here are available targets:"
	@egrep -o "^#: (.+)" [Mm]akefile  | sed 's/#: /* /'

#: venv2 - Build Python2.7 virtual environment
venv2: requirements.txt test.txt
	virtualenv -p python2 venv2
	venv2/bin/pip install -r test.txt
	touch venv2

#: venv3 - Build Python3 virtual environment
venv3: requirements.txt test.txt
	virtualenv -p python3 venv3
	venv3/bin/pip install -r test.txt
	touch venv3

#: venv - Build Python2.7 & Python3 virtual enviroments
venv: venv2 venv3

#: test2 - Run unit tests for Python2.7
.PHONY: test2
test2: venv2
	PYTHONPATH=. venv2/bin/pytest veristack

#: test3 - Run unit tests for Python3
.PHONY: test3
test3: venv3
	PYTHONPATH=. venv3/bin/pytest veristack

#: test - Run unit tests for Python2.7 & Python3
.PHONY: test
test: test2 test3

#: lint - Run code analysis
.PHONY: lint
lint: venv3
	venv3/bin/prospector --profile=prospector --die-on-tool-error

#: check - Alias for lint
.PHONY: check
check: lint

#: clean - Restore working directory to pristine state
.PHONY: clean
clean:
	rm -rf build dist *.egg-info venv2 venv3 htmlcov

#: setup-ubuntu - Install prereqs
.PHONY: setup-ubuntu
setup-ubuntu:
	sudo apt-get install -y python-virtualenv libmysqlclient-dev libxml2-dev libxslt1-dev build-essential python-dev python3-dev

#: ci - Run continuous integration tests
.PHONY: ci
ci: setup-ubuntu clean test lint

#: sdist - Create a tar.gz distribution.
.PHONY: sdist
sdist:
	${MAKE} venv3
	rm -rf dist
	venv3/bin/python setup.py sdist

#: priv-pypi-upload - upload source distribution on private PYPI repo.
.PHONY: priv-pypi-upload
priv-pypi-upload:
	# Note: to reference the uploaded distribution, requirements.txt will
	# need an entry like this:
	#   --extra-index-url http://pypi.dev.veristack.com/root/veristack-duster/+simple/
	#   duster==0.2.315.b00117c
	${MAKE} sdist
	venv3/bin/pip install devpi-client
ifndef PASSWORD
	venv3/bin/python -m devpi login root
else
	venv3/bin/python -m devpi login root --password=$(PASSWORD)
endif
	# Create index (done once)
	# venv3/bin/python -m devpi index --create root/veristack-client-python
	venv3/bin/python -m devpi use http://pypi.dev.veristack.com/root/veristack-client-python
	venv3/bin/python -m devpi  upload -v dist/*.tar.gz
