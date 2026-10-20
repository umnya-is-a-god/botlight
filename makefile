-include .env
export

IP := $(or $(IP),$(shell hostname -I | awk '{print $$1}'))
# compose files listed in COMPOSE_FILE (.env) must exist for every docker compose call
_ := $(shell touch ./docker-compose.override.yml ./docker-compose.ports.yml)

b:
	XRAY_VERSION=$$(sh ./scripts/xray_version.sh) docker compose build
preup:
	bash ./scripts/update.sh &
start: # запуск контейнеров
	touch ./override.env ./docker-compose.override.yml ./config/location.conf ./config/override.conf
	sh ./scripts/ports.sh
	IP=$(IP) VER=$(shell cat VERSION) XRAY_VERSION=$$(sh ./scripts/xray_version.sh) docker compose --env-file ./.env --env-file ./override.env up -d --force-recreate
	-docker image prune -f > /dev/null # old builds of the botlight images
u: preup start
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
delete:
	make d
	docker system prune -f -a
	docker volume prune -f -a
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