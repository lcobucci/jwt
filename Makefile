PARALLELISM := $(shell nproc)

.PHONY: all
all: install phpcbf phpcs phpstan phpunit infection phpbench

.PHONY: install
install: vendor/composer/installed.json

vendor/composer/installed.json: composer.json composer.lock
	@composer install $(INSTALL_FLAGS)
	@touch -c composer.json composer.lock vendor/composer/installed.json

.PHONY: phpunit
phpunit:
	@php -d zend.assertions=1 vendor/bin/phpunit

.PHONY: infection
infection:
	@php -d zend.assertions=1 vendor/bin/phpunit --testsuite=unit --coverage-xml=build/coverage-xml --log-junit=build/junit.xml $(PHPUNIT_FLAGS)
	@php -d zend.assertions=1 vendor/bin/infection -v -s --threads=$(PARALLELISM) --coverage=build --skip-initial-tests $(INFECTION_FLAGS)

.PHONY: phpcbf
phpcbf:
	@vendor/bin/phpcbf --parallel=$(PARALLELISM) || true

.PHONY: phpcs
phpcs:
	@vendor/bin/phpcs --parallel=$(PARALLELISM) $(PHPCS_FLAGS)

.PHONY: phpstan
phpstan:
	@vendor/bin/phpstan analyse --memory-limit=-1

.PHONY: phpbench
phpbench:
	@vendor/bin/phpbench run -l dots --report aggregate
