ifdef CI
	DOCKER_PHP_EXEC :=
else
	DOCKER_PHP_EXEC := docker compose run --rm php
endif
PARALLELISM := $(shell nproc)

.PHONY: all
all: phpcbf phpcs phpstan phpunit infection phpbench

.env: /etc/passwd /etc/group Makefile
	printf "USER_ID=%s\nGROUP_ID=%s\n" `id --user "${USER}"` `id --group "${USER}"` > .env

vendor/composer/installed.json: composer.json composer.lock .env docker-compose.yml Dockerfile
	@$(DOCKER_PHP_EXEC) composer install $(INSTALL_FLAGS)
	@touch -c composer.json composer.lock vendor/composer/installed.json

.PHONY: phpunit
phpunit: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) php -d assert.exception=1 -d zend.assertions=1 vendor/bin/phpunit $(PHPUNIT_FLAGS)

.PHONY: infection
infection: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) php -d assert.exception=1 -d zend.assertions=1 -d xdebug.mode=coverage vendor/bin/phpunit --coverage-xml=build/coverage-xml --log-junit=build/junit.xml $(PHPUNIT_FLAGS)
	@$(DOCKER_PHP_EXEC) php -d assert.exception=1 -d zend.assertions=1 vendor/bin/infection -v -s --threads=$(PARALLELISM) --coverage=build --skip-initial-tests $(INFECTION_FLAGS)

.PHONY: phpcbf
phpcbf: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) vendor/bin/phpcbf --parallel=$(PARALLELISM) || true

.PHONY: phpcs
phpcs: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) vendor/bin/phpcs --parallel=$(PARALLELISM) $(PHPCS_FLAGS)

.PHONY: phpstan
phpstan: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) php -d xdebug.mode=off vendor/bin/phpstan analyse --memory-limit=-1

ifndef PHPBENCH_REPORT
override PHPBENCH_REPORT = aggregate
endif

.PHONY: phpbench
phpbench: vendor/composer/installed.json
	@$(DOCKER_PHP_EXEC) vendor/bin/phpbench run -l dots --retry-threshold=5 --report=$(PHPBENCH_REPORT) $(PHPBENCH_FLAGS)
