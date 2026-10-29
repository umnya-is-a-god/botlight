-include .env
export

IP := $(or $(IP),$(shell hostname -I | awk '{print $$1}'))
# the images' tag: the branch (scripts/images.sh), as docker-compose.yml names them
IMAGE_TAG := $(or $(IMAGE_TAG),$(shell bash ./scripts/images.sh tag))
# compose files listed in COMPOSE_FILE (.env) must exist for every docker compose call
_ := $(shell touch ./docker-compose.override.yml ./docker-compose.ports.yml)

b:
	docker compose build
preup:
	bash $(CURDIR)/scripts/update.sh &
start: # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	@# the working state into ./data (once; nothing is overwritten)
	sh ./scripts/migrate_data.sh
	sh ./scripts/ports.sh
	@# the images as they are; a missing one from GitHub's registry, or built here
	VER=$(shell cat VERSION) bash ./scripts/images.sh ensure
	IP=$(IP) VER=$(shell cat VERSION) docker compose --env-file ./.env --env-file ./override.env up -d --force-recreate --no-build --pull never
	@# images no longer used: the bot's own only (quiet)
	-@bash ./scripts/images.sh prune
u: preup start
images: # новые образы из GitHub (без них — сборка здесь); потом make r. Кнопка бота делает то же с проверкой
	VER=$(shell cat VERSION) bash ./scripts/images.sh update
rebuild: # пересборка образов заново, по одному: свежие базовые образы и пакеты (S=сервис — только его)
	for s in $(or $(S),ng php ad xr oc wp dnstt); do \
		VER=$(shell cat VERSION) docker compose --env-file ./.env --env-file ./override.env build --pull --no-cache $$s || { bash ./scripts/images.sh buildclean; exit 1; }; \
	done
	@# the build cache and the base images: not needed after the build
	bash ./scripts/images.sh buildclean
d: # остановка контейнеров
	-kill -9 $(shell cat ./.update_pid 2>/dev/null) > /dev/null
	docker compose down --remove-orphans
dv: # остановка контейнеров
	docker compose down -v
r: d u
ps: # список контейнеров
	docker compose ps
l: # логи из контейнеров
	docker compose logs
php: # консоль сервиса
	docker compose exec php /bin/sh
ng: # консоль сервиса
	docker compose exec ng /bin/sh
up: # консоль сервиса
	docker compose exec up /bin/sh
ad: # консоль сервиса
	docker compose exec ad /bin/sh
wp: # консоль сервиса
	docker compose exec wp /bin/sh
dnstt: # консоль сервиса
	docker compose exec dnstt /bin/sh
xr: # консоль сервиса
	docker compose exec xr /bin/sh
oc: # консоль сервиса
	docker compose exec oc /bin/sh
service: # консоль сервиса
	docker compose exec service /bin/sh
delete: # полное удаление бота: только его контейнеры, тома, образы, автозапуск и папка
	make uncron
	-kill -9 $(shell cat ./.update_pid 2>/dev/null) > /dev/null
	docker compose down -v --rmi all --remove-orphans
	rm -rf /root/vpnbot
s:
	git status -su
reset: # сброс к начальному состоянию: удаляются все настройки, пользователи, ключи, тома AdGuard и WARP; остаются токен бота и админы
	@printf 'All settings, users and keys are deleted; the bot token and the admins stay. Type yes to go on: '; read a; [ "$$a" = yes ]
	make d
	git reset --hard
	git clean -fd
	@# the working state, except the bot token and the admins (data/config.php)
	find ./data -mindepth 1 -maxdepth 1 ! -name config.php -exec rm -rf {} +
	docker compose down -v --remove-orphans
	make u
backup:
	docker compose exec php php backup.php > backup.json
cron: # установка задачи в cron для автозапуска при перезагрузке
	@(crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r"; echo "@reboot cd /root/vpnbot && make r") | crontab -
uncron: # удаление задачи из cron
	@crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r" | crontab -