-include .env
export

IP := $(or $(IP),$(shell hostname -I | awk '{print $$1}'))
# compose files listed in COMPOSE_FILE (.env) must exist for every docker compose call
_ := $(shell touch ./docker-compose.override.yml ./docker-compose.ports.yml)

b:
	XRAY_VERSION=$$(sh ./scripts/xray_version.sh) docker compose build
preup:
	bash $(CURDIR)/scripts/update.sh &
start: # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	@# the working state into ./data (once; nothing is overwritten)
	sh ./scripts/migrate_data.sh
	sh ./scripts/ports.sh
	IP=$(IP) VER=$(shell cat VERSION) XRAY_VERSION=$$(sh ./scripts/xray_version.sh) docker compose --env-file ./.env --env-file ./override.env up -d --force-recreate
	@# drop superseded builds of the bot's own images only (quiet)
	-@docker image prune -f --filter label=org.botlight.project=vpnbot > /dev/null
u: preup start
rebuild: # пересборка образов заново, по одному: свежие базовые образы и пакеты (S=сервис — только его)
	for s in $(or $(S),ng php ad xr oc wp dnstt); do \
		VER=$(shell cat VERSION) XRAY_VERSION=$$(sh ./scripts/xray_version.sh) docker compose --env-file ./.env --env-file ./override.env build --pull --no-cache $$s || exit 1; \
	done
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
c:
	git add config/
	git checkout .
	git reset
reset:
	make d
	git reset --hard
	git clean -fd
	docker volume rm vpnbot_adguard vpnbot_warp
	make u
backup:
	docker compose exec php php backup.php > backup.json
cron: # установка задачи в cron для автозапуска при перезагрузке
	@(crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r"; echo "@reboot cd /root/vpnbot && make r") | crontab -
uncron: # удаление задачи из cron
	@crontab -l 2>/dev/null | grep -v "cd /root/vpnbot && make r" | crontab -