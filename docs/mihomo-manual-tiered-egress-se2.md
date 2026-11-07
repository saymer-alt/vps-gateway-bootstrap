# Ручная адаптация Mihomo для VPS: эшелонированный выход и Gemini (SE2 V2, 06.11.2026)

> **Операторский runbook / проверенный частично полевой профиль.** Это не установщик и не новый функционал `vps-gateway`. Сначала прочитать [owner design intent](OWNER-THREAT-DRIVEN-RESILIENCE.md), [security model](security-model.md) и корневой [AGENTS.md](../AGENTS.md). Изменения в этом документе **не дают разрешения** агенту самостоятельно изменять живые VPS, расширять scope Core MVP или обходить его gate.

## Решение: вручную адаптировать готовый YAML вместо доработки генератора

Для узкоспециализированной маршрутизации четырех автономных VPS (`SE`, `SE2`, `EE`, `MSK`) владелец выбрал путь: получить исходный Mihomo YAML через `link-generators`, затем **разово адаптировать** его с ИИ и проверкой оператором. Отдельная универсальная функция генератора, UI, миграция/тесты новой функции и последующее сопровождение экономически не оправданы для этой задачи. Никаких изменений `link-generators` ради данного кейса не требуется.

Это **локальная политика каждого VPS**, не единая конфигурация для всех четырех: исходные прокси, адреса, приоритеты, поддерживаемые протоколы и цепочки могут отличаться. Работающий SE2 V2 — референс **метода**, но не готовый YAML для SE/EE/MSK.

## Реальная полевая отметка SE2 (06.11.2026)

| Проверка | Свидетельство / уровень уверенности |
| --- | --- |
| `mihomo.service` работает на SE2; бинарник `/usr/local/bin/mihomo`, `-d /etc/mihomo`, конфиг `/etc/mihomo/config.yaml` | **OBSERVED** по выведенным оператором `ps` и `systemctl cat` (03–06.11.2026) |
| Методы групп `GLOBAL`, `AUTO-EXIT`, `CF-MASQUE`, `GEODEMA`, `KYRA`, `GIST`; провайдеры доступны и видны | **OBSERVED** на скриншотах MetaCubeXD |
| Оператор заменил конфиг V2 и сообщает, что работает; Gemini открывается, 2IP показывает CF | **OPERATOR REPORTED** (06.11.2026) |
| Gemini фактически проходит именно через Geodema | **NOT YET VERIFIED** — нужен журнал соединений / просмотр `Connections` |
| Переключение при принудительном отказе WG, MASQUE, обеих подписок и при полном outage без DIRECT | **NOT YET VERIFIED** — нужна контролируемая отрицательная приёмка |
| Все приложения/VPN-порты VPS автоматически попадают в Mihomo | **НЕ ДОКАЗАНО**: `mixed-port: 7890` обрабатывает только потоки, реально направленные на него, а не автоматически весь трафик хоста |

## SE: Amnezia Gateway — полевая установка 06.11.2026 (gVisor сохранён)

Владелец предоставил **два варианта генератора** для SE: (1) только `mixed-port: 7890`; (2) VPS Transparent Gateway с `tun-mihomo`, `auto-route: false`, `dns: fake-ip`, `dns-hijack` и sniffer. Для SE с работающим `amnezia-mihomo-gateway` **нельзя** переносить локальный вариант SE2 без TUN: AmneziaWG Docker-трафик использует Linux policy-routing в таблице 100 → `tun-mihomo`, а служебные ответы AWG намеренно идут через `fwmark 0x88` и host route. См. [документацию gateway](https://github.com/saymer-alt/amnezia-mihomo-gateway/blob/main/README.md).

- Сверка полей без публикации секретов: SE имеет отдельные от SE2 MASQUE EC P-256 private key, WG private key (32 byte), HWID и WARP IPv6; H2/H3 внутри SE используют один ключ/аккаунт — это ожидаемо. WARP peer public keys для SE и SE2 общие. **Реальная регистрация/handshake не проверялись.**
- Единственные нужные изменения в пользовательских правилах: `GLOBAL → AUTO-EXIT`, приоритеты WG/H3/H2/Geodema/Kyra/Gist, доменные Gemini → `GEODEMA`, no user DIRECT + empty fallback → REJECT. Не ломать существующие TUN/DNS/sniffer, `device: tun-mihomo`, `auto-route: false`.
- **MIPS vs gVisor:** генератор предложил `stack: mips`, но gateway README фиксирует `gvisor` как сравнительно проверенный VPS baseline (21.09.2026). Не менять stack вместе с routing без фактического live-check и отдельного согласования. Переносить фактически работающий стек; при одинаковой функциональности предпочитать подтверждённый gVisor.
- `dns.listen: 0.0.0.0:53` требует контроля конфликтов с другим DNS-слушателем и защиты от публичного доступа firewall'ом. Это операторская проверка, а не рекомендация открыть резолвер.
- Первые варианты SE были **без** `exclude-filter`; 06.11.2026 оператор отдельно дал свой фильтр российских узлов и Kyra Telegram. В окончательном рабочем YAML проверено **три вхождения** `exclude-filter` — по одному в Geodema/Kyra/MyGist. Сам приватный YAML/полный provider regex в публичный репозиторий не выкладывать.
- **Подтверждено владельцем, 06.11.2026:** SE (`Saymer`) работает с `/usr/local/bin/mihomo` **v1.19.33** и `/etc/mihomo/config.yaml`, `ExecStart=/usr/local/bin/mihomo -d /etc/mihomo`. Рабочий `tun.stack: gvisor` (MIPS **не внедряли**, сравнительный тест отложен), `device: tun-mihomo`, `auto-route: false`, `mtu: 1420`, `gso: true`, DNS hijack, `disable-icmp-forwarding: true`. Следующие live-проверки маршрутов и firewall см. ниже.
- До обновления: проверить `ps aux | grep '[m]ihomo'`, `systemctl cat mihomo`, `grep -A12 '^tun:' <active-yaml>` (без секретов), `ip -4 rule`, `ip -4 route show table 100`, `ip link show tun-mihomo`, `systemctl status warp-docker-routing.service check-warp-routing.timer`, `ss -lntup`; после — тест `mihomo -t`, явный owner-applied restart, внешний IP через 7890 **и** подключённого AWG-клиента, Gemini chain и fail-closed.

### Read-only факты SE (оператор, 06.11.2026 16:24 MSK)

- Unit: `/etc/systemd/system/mihomo.service`; `ExecStart=/usr/local/bin/mihomo -d /etc/mihomo`; бинарник Mihomo **v1.19.33**.
- Реальный фрагмент активного YAML: `stack: gvisor`, `device: tun-mihomo`, `mtu: 1420`, `gso: true`, `auto-route: false`, `dns-hijack: [any:53, tcp://any:53]`, `disable-icmp-forwarding: true`.
- `ip -4 rule`: `40: from all fwmark 0x88 lookup main`; `100: from 172.29.172.0/24 lookup mihomo`.
- `ip -4 route show table 100`: `default dev tun-mihomo scope link metric 10` и `unreachable default metric 42760`; присутствие blackhole-предохранителя **CONFIG OBSERVED**, не равно end-to-end fail-closed proof.
- `tun-mihomo`: `198.18.0.0/30`, `UNKNOWN` как link state для TUN — не автоматический признак ошибки.
- `warp-docker-routing.service`: active (exited), success; `check-warp-routing.timer`: active (waiting), включен.
- Память: total **913 MiB**, available **161 MiB**; swap used **368 MiB / 1.5 GiB**. При MIPS/gVisor бенчмарке фиксировать swap/CPU/load до и после, сравнивать **на AWG-клиенте**, а не через локальный mixed-port.
- Эти факты снимают неопределенность относительно маршрутов/юнита в момент вывода, но **не подтверждают** работу AWG клиентского dataplane после замены и реального отказа всех прокси.
- Оператор хочет отдельное сравнительное испытание `gvisor` vs `mips` на SE, не меняя остальных параметров. Не считать факт поддержки MIPS доказательством выигрыша по скорости; эксперимент после сохранения baseline и с rollback.

**Статус SE (06.11.2026, 17:00 MSK):** полный YAML изменён оператором и `mihomo -t` вернул PASS; `mihomo.service` ACTIVE; `tun-mihomo` и таблица 100 восстановлены; DNS TCP+UDP 53 обслуживает Mihomo без ошибки нового запуска; watchdog active; UFW active. **AWG client egress, Gemini фактический chain, speed и полный failover/отказ — NOT VERIFIED**. Итог рабочего состояния — только по фактам из предоставленных владельцем команд, не прямой доступ к VPS.

### SE — фактическое завершение, инциденты и важные границы (06.11.2026)

**Что сделал и проверил оператор на SE:**
1. Исходный вариант Gateway имел `gvisor`; после редактирования через `nano` текущий V2 успешно прошёл `/usr/local/bin/mihomo -t -d /etc/mihomo`. При следующем запуске процесс `mihomo.service` — `active (running)`, интерфейс `tun-mihomo` присутствует, `198.18.0.0/30`.
2. Из-за перезапуска Mihomo временно исчез `default dev tun-mihomo` из table 100, остался только `unreachable default metric 42760`. `systemctl restart warp-docker-routing.service` завершился с `SUCCESS`, вернул `default dev tun-mihomo scope link metric 10` при сохранении unreachable barrier; `check-warp-routing.timer` active. **Не считать присутствие TUN достаточной проверкой таблицы маршрутов!**
3. `systemd-resolved` был active+enabled и владел портом 53 на `127.0.0.53/54`; Mihomo логировал `Start DNS server(TCP|UDP) ... bind: address already in use`, оставаясь `active`. `/etc/resolv.conf` уже был обычным, immutable-файлом с `1.1.1.1` и `8.8.8.8`, а не symlink на stub. После явного отключения `systemd-resolved` (`disable --now`) `getent ahostsv4 github.com` отработал; Mihomo перезапущен и Gateway routing перезапущен **ещё раз**. Финальные `ss` показывают, что только Mihomo слушает `*:53` TCP+UDP; в логах после нового запуска 17:00 не было bind errors.
4. UFW active: default `deny (incoming)`, `deny (routed)`; в видимых правилах нет открытия 53 снаружи. `iptables -S INPUT` — DROP, вход через UFW. **Не доказано внешним сканированием**, что весь DNS ingress на 53 закрыт, поэтому это `CONFIG OBSERVED`, не `EXTERNAL EXPOSURE TEST PASS`.
5. `grep -c 'exclude-filter:' /etc/mihomo/config.yaml` → **3**. Режим MIPS владелец явно **отложил**, оставив gVisor как рабочий baseline; не инициировать новый бенчмарк без нового запроса.

**Инцидент процедуры:**
- `mihomo -t -f /etc/mihomo/config.yaml.candidate` для **несуществующего** candidate вывел `Can't find config, create a initial config file` и `test is successful`; вслед за этим копирование созданной начальной конфигурации в `config.yaml` убрало TUN. Позже перезапись с неверной кодировкой привела к `yaml: invalid leading UTF-8 octet`. Полагаться на слово `successful` без проверки файла — **опасно**.
- Резервная копия `/etc/mihomo/config.yaml.before-v2`, однажды существовавшая, позже оказалась отсутствующей по ожидаемому пути после файловых операций. Для будущих хостов **не рассчитывать на бэкап внутри каталога**, если его перезаписывают или заменяют целиком; держать отдельную копию в `/root/` с проверенным `test -s` и правами 600.
- Перед применением требовать **ровно тот файл**, который изменён оператором, с корректным UTF-8, полноценными секциями `tun:`, `proxy-groups:` и `rules:`. Если candidate физически отсутствует, **не запускать тест по отсутствующему пути**, поскольку в этой версии это не fail-closed. Проверка по месту — обязательна:

```bash
# READ-ONLY, host-specific after discovery (пример SE):
test -s /etc/mihomo/config.yaml || exit 1
grep -q '^tun:' /etc/mihomo/config.yaml || exit 1
grep -q '^proxy-groups:' /etc/mihomo/config.yaml || exit 1
grep -q '^rules:' /etc/mihomo/config.yaml || exit 1
/usr/local/bin/mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml || exit 1
# Затем после разрешенного оператором restart — проверить не только unit, но и
# TUN, ip rule/table 100, Gateway watchdog, DNS bind warnings и AWG egress.
```

**Нельзя автоматически переносить на EE/MSK** отключение `systemd-resolved`, `dns.listen: 0.0.0.0:53`, gVisor или gateway table 100: это было узко проверено только на SE, где `/etc/resolv.conf` уже независимый immutable-файл. Для иных хостов сначала определить владельца DNS, сервисный путь и контракт маршрутизации.

## Политика SE2 V2

- `mode: rule` сохраняется: **никогда не включать фактический режим Mihomo `global`**, если нужно исключение Gemini. `GLOBAL` — имя группы `type: select`, а не режим работы ядра.
- `mixed-port: 7890`, `allow-lan: false`, `external-controller: 127.0.0.1:9090`; проверьте реальных клиентов/коннекторы перед переносом на другой VPS.
- `rules`: специфические правила Gemini/Google AI **раньше** `MATCH,GLOBAL`; Gemini назначается `GEODEMA` независимо от выбранного `GLOBAL`. Нельзя автоматически переключать Gemini на WARP, если Geodema недоступна: для этого правила нужен отказ (fail closed).
- Схема по умолчанию: `GLOBAL (select) → AUTO-EXIT (fallback)`. В `AUTO-EXIT` строго: (1) WARP WG, (2) CF MASQUE H3/QUIC, (3) CF MASQUE H2, (4) GEODEMA, (5) KYRA, (6) GIST, (7) REJECT.
- `CF-MASQUE` — отдельно выбираемая группа только из H3/H2; не вкладывать ее внутрь `AUTO-EXIT` (уменьшение риска с nested fallback, [Mihomo #2588](https://github.com/MetaCubeX/mihomo/issues/2588)).
- `GEODEMA` / `KYRA` / `GIST`: отдельные `url-test` по собственному `use` provider и `empty-fallback: REJECT`. Это сохраняет внутри каждой подписки выбор рабочего узла; **не считается доказательством** корректного перехода между вложенными группами при полном отказе всех их узлов.
- **Никакого пользовательского DIRECT** ни в `rules`, ни в `GLOBAL`/`AUTO-EXIT`. `REJECT` в финале используется как политика отказа, не как механизм автоматического переключения.
- `empty-fallback: REJECT` предотвращает неявный `COMPATIBLE`/прямой выход при **пустой** группе. Это не равно «когда все существующие узлы unhealthy» и само по себе не доказывает безопасный failover. У пользовательских групп с потенциально пустыми провайдерами держать явно.
- Служебный `proxy: DIRECT` для скачивания подписок/bootstrap (или отсутствие ключа `proxy`) **не является** разрешением пользовательского прямого egress. Контроль service-plane отдельно от user data-plane; см. [no-DIRECT invariant](https://github.com/saymer-alt/link-generators/blob/main/docs/NO-DIRECT-INVARIANT.md).
- Загрузка провайдеров и health-check сами по себе могут выходить с IP VPS; не путать их с пользовательскими потоками.
- `REJECT` в `GLOBAL` допустим для ручного полного отключения; в `CF-MASQUE` отдельный ручной `REJECT` не нужен.
- `store-selected: true` сохраняет выбор; после применения обязательно сверить, что по умолчанию активен `AUTO-EXIT`, а не прежняя сохраненная ручная группа.

### Безопасный синтетический каркас (НЕ готовый конфиг)

Ниже **только часть** групп: узлы, подписки, Gemini rules, sniffer и credentials берутся из приватного оригинала на конкретном VPS.

```yaml
mode: rule
mixed-port: 7890
allow-lan: false
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [AUTO-EXIT, WARP-WG, CF-MASQUE, GEODEMA, KYRA, GIST, REJECT]
  - name: AUTO-EXIT
    type: fallback
    proxies: [WARP-WG, WARP-MASQUE-H3, WARP-MASQUE-H2, GEODEMA, KYRA, GIST, REJECT]
    url: https://www.gstatic.com/generate_204
    interval: 120
    lazy: false
    empty-fallback: REJECT
  - name: CF-MASQUE
    type: fallback
    proxies: [WARP-MASQUE-H3, WARP-MASQUE-H2]
    url: https://www.gstatic.com/generate_204
    interval: 120
    empty-fallback: REJECT
  - name: GEODEMA
    type: url-test
    use: [Geodema-PROVIDER]
    url: https://www.gstatic.com/generate_204
    interval: 180
    empty-fallback: REJECT
  - name: KYRA
    type: url-test
    use: [Kyra-PROVIDER]
    url: https://www.gstatic.com/generate_204
    interval: 180
    empty-fallback: REJECT
  - name: GIST
    type: url-test
    use: [Gist-PROVIDER]
    url: https://www.gstatic.com/generate_204
    interval: 180
    empty-fallback: REJECT
rules:
  - DOMAIN,gemini.google.com,GEODEMA
  - DOMAIN,aistudio.google.com,GEODEMA
  - DOMAIN,generativelanguage.googleapis.com,GEODEMA
  # Добавить и актуализировать прочие специфичные Gemini-хосты после наблюдений.
  - MATCH,GLOBAL
```

Синтетический пример **специально не содержит** настоящих WARP keys, URL подписок, HWID, IP серверов, controller secrets, client IP и готовой схемы `proxy-providers`. Никогда не публиковать живой конфиг в GitHub, issues, CI-логи или support dumps. Имена в реальном файле должны совпадать с фактическими узлами и провайдерами.

### Gemini vs YouTube

- `gemini.google.com`, AI Studio и специфичные Gemini API → `GEODEMA` (порядок правил перед `MATCH`).
- `youtube.com`, `googlevideo.com` и прочий обычный трафик не имеют отдельного правила в профиле SE2 V2 → `GLOBAL`, **обычно** WARP, при недоступности WARP — следующий рабочий резерв, включая Geodema.
- Не добавлять правила на весь `google.com`, `googleapis.com` или `gstatic.com`, иначе можно непреднамеренно отправить чужие приложения/YouTube через платную подписку.
- Открывающийся Gemini **не доказывает** выход через Geodema. В MetaCubeXD `Connections` / journal отдельно проверить фактическое `Rule`/`Chain` для Gemini; ECH, IP-only и shared Google endpoints могут ограничивать точность доменной классификации.

## Процедура для каждого следующего VPS — только с отдельным owner GO

**READ-ONLY discovery:** до изменения `ps aux | grep '[m]ihomo'`, `systemctl cat mihomo`, `systemctl status mihomo --no-pager -l`, посмотреть текущий конфиг локально **без передачи секретов в публичные источники**; установить активный путь, `-d`/`-f`, бинарник, порты, users, правила, существующие цепочки. Не переносить `/etc/mihomo` или systemd-настройки SE2 на другой сервер по умолчанию.

**OPERATOR WRITE (явно разрешенная локальная процедура):** копия исходного файла с меткой времени, кандидат в отдельном файле, проверка `mihomo -t -d <active-dir> -f <candidate>` **до** подмены, только затем разрешенная замена и restart соответствующего unit. Пример SE2:

```bash
# Read only:
ps aux | grep '[m]ihomo'
systemctl cat mihomo
# Operator backup / staging, SE2 only:
cp -a /etc/mihomo/config.yaml /etc/mihomo/config.yaml.bak-$(date +%Y%m%d-%H%M%S)
# Save new private YAML separately as /etc/mihomo/config.yaml.candidate
/usr/local/bin/mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml.candidate
# ONLY on PASS and explicit host-specific operator authorization:
# cp -a /etc/mihomo/config.yaml.candidate /etc/mihomo/config.yaml
# systemctl restart mihomo
# systemctl status mihomo --no-pager -l
```

Строки замены и рестарта намеренно закомментированы. Этот документ не расширяет mutation authority `vps-gateway-bootstrap`; ручные действия владельца — вне автоматизированного Core.

**POST-CHANGE acceptance:** (1) `mihomo -t` PASS, unit active, controller/7890 доступны ожидаемым клиентам; (2) `curl -4 -x http://127.0.0.1:7890 https://api.ipify.org` показывает не IP VPS, а ожидаемый WARP/другой разрешенный egress; (3) наблюдаемый Gemini → Geodema по `Connections`; (4) YouTube → GLOBAL/ожидаемый выход; (5) изучить failover/failback и полный outage в **ограниченном, заранее согласованном тесте**, не ломая рабочую продакшен-маршрутизацию и не подменяя результаты одним HTTP 204; (6) после проблемы восстановить **точную** резервную копию и проверить эффективный runtime. Не выдавать результат теста одной машины за остальные.

### Состояние тиражирования

| Host | Состояние |
| --- | --- |
| SE2 (`Saymer2`) | V2 применена владельцем, функциональная smoke-проверка **reported PASS**, negative outage и точный маршрут Gemini — **UNKNOWN** |
| SE (`Saymer`) | V2 с Gateway применена владельцем; `mihomo -t` PASS, unit/TUN/DNS/routes/firewall см. field evidence — **CONFIG + SERVICE OBSERVED PASS**; внешний egress с AWG-клиента / Gemini chain / outage — **UNKNOWN**. `gvisor` сохранён; MIPS отложен |
| EE (`hungry-boyd`) | **V4 APPLIED / WG FIELD PASS:** три отдельных WARP-WG peer, API задержки 24/21/14 мс; `AUTO-EXIT.now=WARP-WG-EE-1`, `GLOBAL.now=AUTO-EXIT`. Gemini фактически `gemini.google.com → польский узел → GEODEMA`, HTTP 200. DNS TCP+UDP 53 и TUN/routes восстановлены; AWG client egress и outage ещё не доказаны |
| MSK (`Saymer3`) | **V2 operator-applied and runtime smoke PASS; V3 operator reports improved, NOT YET VERIFIED.** 07.11 V2 — new Mihomo PID after restart, DNS TCP/UDP :53, TUN + policy rules 40/100 and table100 fail-secure terminal, watchdog next scheduled; local proxy HTTP 204, `GLOBAL→AUTO-EXIT→Estonia TUIC`. Mieru(TCP) and WARP had `alive=false`, provider group health unknown. V3 changed Mieru→UDP, AWG identity/options, removed duplicate visible REJECT; no post-V3 field API/negative outage proof. [MSK incident and gates](msk-mihomo-v2-v3-field-lessons-2026-11-07.md) |


## Полевое дополнение — EE V4 и MSK до нового YAML (06.11.2026)

Эта секция актуализирует ранние записи «EE/MSK NOT STARTED» выше, не стирая историю решений и не выдавая результаты unit/локального прокси за клиентскую E2E-приёмку.

### EE: отказ WG, затем три рабочих независимых WG

- В EE V2 после перезагрузки `GLOBAL.now=WARP EE`, при этом `WARP EE.alive=false` и задержки 0. `profile.store-selected:true` восстановил ручной выбор сломанного WG в обход `AUTO-EXIT`; это отдельная ошибка от неисправного peer. Причину недоступности старой пары ключи/endpoint (`162.159.198.187:443`) **не выделили** из взаимозависимых изменений.
- EE V4: `store-selected:false`; `GLOBAL → AUTO-EXIT`, первыми идут WG1 `8.34.146.122:2408`, WG2 `188.114.98.249:2408`, WG3 `188.114.97.113:2408`, далее MASQUE H3/H2 → Geodema → Kyra → Gist → REJECT. Владелец **явно решил сохранить все три WG** (не объединение каналов: fallback выбирает первый живой).
- Mihomo `-t` PASS; API задержки трёх WG: 24/21/14 мс, `AUTO-EXIT.now=WG1`, `GLOBAL.now=AUTO-EXIT`; живой Gemini chain через Geodema подтверждён. Три рабочих WG сейчас — **не** доказательство отказоустойчивости при принудительной потере всех транспортов.
- Код генератора по этому случаю не выпускается автоматически; требования сохранены в [link-generators #278](https://github.com/saymer-alt/link-generators/issues/278).

### MSK: DNS и планировщик/маршруты — восстановлены оператором

- Ubuntu 24.04.5, Mihomo 1.19.33, `gvisor`, `tun-mihomo`, Docker AWG bridge `172.29.172.0/24`, отдельный host-network контейнер radio. Начальный `mihomo.service active` не означал рабочий DNS: journal показал отказ TCP+UDP `0.0.0.0:53` из-за `systemd-resolved`. После проверки самостоятельного immutable `/etc/resolv.conf` владелец остановил и отключил resolved, рестартовал Mihomo и выполнил **reload** Gateway. Mihomo занял TCP+UDP 53; `getent github.com` PASS, прокси `gstatic generate_204` HTTP 204.
- `warp-docker-routing.service` был `active (exited)`, хотя отсутствовали приоритеты `ip rule 40/100` и `unreachable default` в table 100. При этом independent `AMG_FAILSECURE` цепочка с REJECT и FORWARD DROP сохранились (отсутствие реальной утечки не доказано).
- Root cause **несрабатывания watchdog**: локальный `check-warp-routing.timer.d/override.conf` имел пустой `OnUnitActiveSec=`, который сбрасывает все `On*Sec` из базового unit, включая `OnBootSec=2min`. Оставался лишь `OnUnitActiveSec=5min` без первого запуска: `active(elapsed)`, next infinity. Оператор добавил `OnActiveSec=2min`, сохранил `OnUnitActiveSec=5min`, выполнил `daemon-reload` + restart таймера. Первый реальный check `22:53:40 MSK`: `status=0/SUCCESS`, следующий через пять минут.
- Маршруты восстановлены `systemctl reload warp-docker-routing.service`: `ip rule 40 fwmark 0x88 lookup main`, `ip rule 100 from AWG lookup mihomo`, `default dev tun-mihomo metric 10`, `unreachable default metric 42760`; `AMG_FAILSECURE` сохранён. Исходную причину исчезновения правил **не установили**.
- Факты оформлены в [AMG #59](https://github.com/saymer-alt/amnezia-mihomo-gateway/issues/59) (DNS, реализованный install-time gate уже слит в main через PR #60) и [AMG #61](https://github.com/saymer-alt/amnezia-mihomo-gateway/issues/61) (таймер/маршруты; общего исправления в коде пока нет). Настройку YAML MSK V2 **ещё не выполняли**.

**Общие границы:** live WG delays, локальный proxy HTTP 200/204, socket ownership, systemd active и даже один успешный watchdog check НЕ подтверждают end-to-end dataplane AWG, безопасный отрицательный outage, переносимость к другим хостам или доступность DNS 53 с внешнего интерфейса. Полные приватные YAML, WARP private keys, subscription/HWID не коммитить.

## Московская адаптация V2→V3 (07.11.2026)

Уже после восстановления baseline 06.11 оператор применил отдельный MSK V2, затем V3. **Читать текущую полевую отметку и regression checklist в [MSK V2→V3](msk-mihomo-v2-v3-field-lessons-2026-11-07.md)**. Не копировать приоритеты с EE: у Москвы порядок **Estonia Mieru UDP → Estonia TUIC → Geodema → Kyra → Gist → WARP MSK**, а Gemini всегда только через Geodema. 

Запомнить отличие **дискового YAML от активного процесса**: на первом снимке после замены файл уже был новым, но прежний PID работал со вчера; после явного рестарта появился новый PID и прошёл реальный HTTP 204. Не утверждать, что V2 "сломал синтаксис" или что V3 полностью исправил WARP — таких подтверждений не было. Во вложенных fallback не дублировать видимый `REJECT`; `empty-fallback:REJECT` сохраняется как отдельная опция и не заменяет негативные тесты.

## Негативные тесты и условия STOP

Не считать готовым, если `COMPATIBLE`/`DIRECT` появился в пользовательском `Chain`, при пустом provider есть неконтролируемый выход на IP VPS, `MATCH` обходит правило Gemini, бинарник отвергает YAML, auto-fallback остается на мертвом вложенном узле, порт не слушается, пропал доступ к SSH или сломан сторонний входящий сервис. При UNKNOWN остановиться, сохранить working backup, диагностировать, не вводить новый демон/генератор ради одного кейса.

**Главный результат:** доказанная владельцем работоспособность SE2 V2 достаточна, чтобы зафиксировать ручной метод и применить его поочередно к другим хостам. Это не E2E-подтверждение всех fail-closed/negative-path инвариантов.
