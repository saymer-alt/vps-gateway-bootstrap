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

## SE: Amnezia Gateway в отличие от локального SE2 (кандидат 06.11.2026, НЕ применён)

Владелец предоставил **два варианта генератора** для SE: (1) только `mixed-port: 7890`; (2) VPS Transparent Gateway с `tun-mihomo`, `auto-route: false`, `dns: fake-ip`, `dns-hijack` и sniffer. Для SE с работающим `amnezia-mihomo-gateway` **нельзя** переносить локальный вариант SE2 без TUN: AmneziaWG Docker-трафик использует Linux policy-routing в таблице 100 → `tun-mihomo`, а служебные ответы AWG намеренно идут через `fwmark 0x88` и host route. См. [документацию gateway](https://github.com/saymer-alt/amnezia-mihomo-gateway/blob/main/README.md).

- Сверка полей без публикации секретов: SE имеет отдельные от SE2 MASQUE EC P-256 private key, WG private key (32 byte), HWID и WARP IPv6; H2/H3 внутри SE используют один ключ/аккаунт — это ожидаемо. WARP peer public keys для SE и SE2 общие. **Реальная регистрация/handshake не проверялись.**
- Единственные нужные изменения в пользовательских правилах: `GLOBAL → AUTO-EXIT`, приоритеты WG/H3/H2/Geodema/Kyra/Gist, доменные Gemini → `GEODEMA`, no user DIRECT + empty fallback → REJECT. Не ломать существующие TUN/DNS/sniffer, `device: tun-mihomo`, `auto-route: false`.
- **MIPS vs gVisor:** генератор предложил `stack: mips`, но gateway README фиксирует `gvisor` как сравнительно проверенный VPS baseline (21.09.2026). Не менять stack вместе с routing без фактического live-check и отдельного согласования. Переносить фактически работающий стек; при одинаковой функциональности предпочитать подтверждённый gVisor.
- `dns.listen: 0.0.0.0:53` требует контроля конфликтов с другим DNS-слушателем и защиты от публичного доступа firewall'ом. Это операторская проверка, а не рекомендация открыть резолвер.
- Для SE **нет** `exclude-filter` в двух представленных исходниках; не копировать ограничения SE2 на RU-узлы без отдельного решения владельца.
- **Новые факты от владельца, 06.11.2026:** SE (`Saymer`) работает с `/usr/local/bin/mihomo` **v1.19.33**, вывод `Use tags: with_gvisor`; текущий файл `/etc/mihomo/config.yaml` содержит `tun.stack: gvisor`, `device: tun-mihomo`, `auto-route: false`, `mtu: 1420`, `gso: true`, DNS hijack и `disable-icmp-forwarding: true`. Это доказывает текущий baseline стека по конфигу, но **не** целостность маршрутов AWG и не безопасность обновления. Путь systemd `-d/-f`, firewall, table 100 и runtime connections на SE пока **UNKNOWN**.
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

**Статус:** офлайн-сверка структуры и ключевых различий — PASS; бинарный Mihomo parse и live Gateway smoke — **NOT TESTED**.

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
| SE | Приватный YAML от оператора рассмотрен, создан офлайн-кандидат V2 с Gateway; live discovery и установка — **NOT STARTED** |
| EE | То же; **NOT STARTED**. Исторически на EE был `tun-mihomo` и policy routing для AWG (09.2026): проверить актуальность и сохранить TUN/rules, не подменять профилем SE2 |
| MSK | То же; возможны отдельные транзитные/меж-VPS пути, не перетирать и исключить циклы маршрутизации; **NOT STARTED** |

## Негативные тесты и условия STOP

Не считать готовым, если `COMPATIBLE`/`DIRECT` появился в пользовательском `Chain`, при пустом provider есть неконтролируемый выход на IP VPS, `MATCH` обходит правило Gemini, бинарник отвергает YAML, auto-fallback остается на мертвом вложенном узле, порт не слушается, пропал доступ к SSH или сломан сторонний входящий сервис. При UNKNOWN остановиться, сохранить working backup, диагностировать, не вводить новый демон/генератор ради одного кейса.

**Главный результат:** доказанная владельцем работоспособность SE2 V2 достаточна, чтобы зафиксировать ручной метод и применить его поочередно к другим хостам. Это не E2E-подтверждение всех fail-closed/negative-path инвариантов.
