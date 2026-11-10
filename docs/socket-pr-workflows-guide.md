# Socket POC

## Поведение проверок

| Результат | Native CLI | Наша server-policy проверка | VEX проверка |
|---|---|---|---|
| Block | красный | красный | красный, если не снят применимым VEX |
| Warn | зелёный с отчётом | красный | красный, если не снят применимым VEX |
| Monitor | зелёный | зелёный с отчётом | зелёный с отчётом |
| Ignore | зелёный | зелёный | VEX рассматривается независимо от native Resolutions |
| Неполные данные / инфраструктурный сбой | штатный ненулевой CLI exit | код 2 | код 2 |

Severity CVE и action политики — разные поля. Critical CVE с Monitor не делает нашу проверку красной.
Коды нашей обвязки: 0 — нет Block/Warn; 1 — есть Block/Warn; 2 — проверка не завершена.
Коды самого Socket CLI не имеют такого строгого разделения: его 1 может означать как policy Block, так и ошибку исполнения.

Все jobs пока необязательны для merge. Их красный статус не запрещает merge, пока GitHub rulesets/required checks не требуют их прохождения.
`continue-on-error` не используется. Исходный `.github/workflows/socket.yaml` не изменён.

## Workflow и файлы

- `socket-native-pr.yaml`: отдельный штатный CLI workflow без нашей policy-проверки; при Warn весь workflow зелёный.
- `socket-vex-pr.yaml`: два независимых PR jobs для сравнения server-policy и собственного VEX verdict.
- `socket-develop-baseline.yaml`: обычный baseline develop и независимый reachability job.
- `socket-scan.yaml`: общий reusable workflow. Установка, checkout, секрет и artifact объявлены один раз.

Файл `socket-pr-test.yaml` переименован в `socket-develop-baseline.yaml`.
Тонкие caller workflows задают ref, название ветки и режим; reusable workflow выполняет общие шаги.
Четыре обычных Python-модуля заменили прежние скрипты с динамическими импортами:

| Файл | Назначение |
|---|---|
| `.github/scripts/socket_scan.py` | Создание scan, API, VEX orchestration, проверка dashboard head и классификация ошибок |
| `.github/scripts/socket_report.py` | Нормализация findings, Block/Warn verdict, Summary и лог |
| `.github/scripts/socket_vex.py` | Точное сопоставление npm identity/CVE и выбор первого применимого statement |
| `.github/scripts/socket_vex_sources.py` | Области применимости источников и чтение доверенных Git snapshots |
| `.github/scripts/install-socket-cli.sh` | Установка CLI после проверки хешей |
| `.github/tools/socket-cli/dependencies.lock` | Socket 1.13.1 и транзитивные зависимости с integrity hashes |
| `.github/socket-vex-sources.json` | Собственный продукт, репозитории и refs VEX |

## Нативный запуск

Job Native CLI verdict запускает напрямую:

```sh
socket scan create --org "$SOCKET_ORG" --repo "$SOCKET_REPO" \
  --branch "$SCAN_BRANCH" --commit-hash "$(git rev-parse HEAD)" \
  --no-set-as-alerts-page --report --report-level warn --markdown .
```

Выход проходит через tee в файл; Bash pipefail сохраняет исходный ненулевой CLI verdict.
Наш Python evaluator здесь не вызывается. Markdown штатного CLI добавляется в Summary без изменения verdict.
Поэтому этот job должен быть зелёным при одних Warn, а Server Block and Warn в другом workflow — красным.
Оба проверяют весь снимок PR, каждый создаёт собственный scan. Это демонстрационное сравнение, а не рекомендуемое дублирование для каждого production PR.
`--report-level warn` управляет отображением алертов, а не превращает Warn в Block.
Native CLI может повторно применять правила по типу алерта и отличаться от серверного alert.action.

## Baseline и reachability develop

Оба jobs сканируют отдельный настоящий checkout develop, а не содержимое тестового PR под меткой develop.
Точный SHA читается внутри checkout и записывается в отчёт. Tooling находится в соседнем checkout и не попадает в scan target.

Обычный baseline использует `--default-branch --set-as-alerts-page` и проверяет через API,
что `default_branch=develop` и `head_full_scan_id` совпадает с созданным scan.
Для этой проверки нужен Socket token scope `repo:list`. Это чтение Socket metadata, не GitHub write.
Baseline питает страницы Dependencies/Alerts. PR и reachability scans используют `--no-set-as-alerts-page` и не заменяют основной baseline.

Отдельный job Develop reachability with SCA fallback использует:

```sh
--reach --reach-version 15.14.1 --reach-disable-analytics \
--reach-analysis-timeout 5m --reach-analysis-memory-limit 4GB \
--reach-fallback-to-regular-scan
```

Он независим от обычного baseline: нет needs, отмены другого job или публикации dashboard head.
Это manifest inventory плюс локальный full application static analysis. Явного yarn build / Docker build в workflow нет.
Engine может скачивать анализаторы и зависимости; для некоторых экосистем необходим build toolchain.
CLI закреплён SHA-512 пакета и SHA-256 lockfile. `--reach-version` выбирает версию engine; это не отдельное закрепление engine по хешу.

При глобальном отказе reachability CLI пытается обычный SCA. Поле `reachabilityFallback` из JSON сохраняется в report.json.
Успешный SCA fallback не доказывает, что full application reachability выполнен.
Если fallback SCA находит Block/Warn, job всё равно красный; один Monitor оставляет его зелёным.
Отказ Socket API этим флагом не устраняется. Чтение API повторяется до трёх раз при временных сетевых/5xx/429 ошибках;
401/403 не повторяются. Неидемпотентное создание scan автоматически не повторяется.

Summary нашей проверки разделён на три самостоятельных раздела:

1. Findings — счётчики, Block/Warn и отдельная сворачиваемая таблица Monitor.
2. Reachability and fallback — не запрошен / запрошен без глобального fallback / переход на обычный SCA.
3. Infrastructure and verification errors — отдельная причина и фаза отказа; код 2, а не утверждение об отсутствии CVE.

Unknown/missing_support для отдельной CVE не равнозначны падению процесса. Персональная reachability metadata остаётся в findings.json.
Успех создания scan сам по себе не означает отсутствие алертов или полное reachability coverage.

После merge baseline запускается при push в develop; также предусмотрен ручной запуск.
До merge новый workflow-файл может отсутствовать в списке workflow default branch. Для проверки из ветки POC:
Actions → Socket native CLI PR → Run workflow → socket-pr-analysis → run_develop_checks=true.
Этот ручной режим вызывает именно переименованный develop workflow, без PR jobs.

## Области применимости VEX

| Источник | Допустимые продукты | Приоритет |
|---|---|---|
| Собственный vexel | Manifest, приложение, Docker image, DHI image | 1 |
| Docker DHI advisories | Только подтверждённые DHI images | 2 |
| Aqua VEX Hub, используемый Trivy | Только Docker images в принятой нами модели | 3 |

Это выбранная организационная политика источников. Сам Trivy умеет сканировать и другие типы targets;
ограничение Aqua до images здесь является нашим правилом применимости.
«Собственный VEX для всего» означает допустимость источника для любого типа продукта,
а не глобальное исключение каждой CVE: должны совпасть продукт, пакет, версия и advisory.

Приоритет применяется только после проверки области применимости.
Текущие Socket jobs — manifest/application scans. Поэтому читается собственный источник;
Docker DHI и Aqua отмечаются как ineligible и не скачиваются. Для full application --reach это тоже не image scan.
Изменить один env-флаг недостаточно, чтобы подтвердить DHI image: будущему image gate нужны digest, архитектура и проверенное происхождение.
Текущий matcher поддерживает точные npm PURL. Общая обработка OS packages и image-product identities ещё не реализована.

Для одной package/version/CVE первое подходящее statement побеждает.
not_affected/fixed снимает finding; affected/under_investigation сохраняет исходное действие и останавливает нижние исключения.
В частности, Monitor + affected остаётся Monitor и даёт 0: VEX сам не повышает action до Warn.
В VEX-варианте server Ignore для vulnerability сначала восстанавливается до Monitor,
чтобы native Resolutions не становились неявным вторым механизмом исключений.
VEX меняет наш Actions verdict; dashboard Socket не переписывается.

## Что найдено в lidofinance actions

Изучены main `1d7a6d8cc9512545dfdda0be7e697a11e7292241` и
[PR 28](https://github.com/lidofinance/actions/pull/28), commit `88e2c5058d81edbf239a37a7f45f474f3c579bce`.
На main Trivy/VEX пока нет. В PR 28:

- reusable k8s-build-push-harbor workflow собирает локальный Docker image до логина в Harbor;
- Trivy 0.62.1 запущен Docker-образом, закреплённым digest;
- `vex repo download` загружает репозитории из доверенного repository.yaml;
- `trivy image --vex repo --skip-vex-repo-update --show-suppressed --format json --exit-code 0` формирует отчёт;
- отдельный Python helper считает findings после VEX; dev report-only, staging/prod/critical блокируются по HIGH/CRITICAL;
- JSON envelope проверяется, чтобы отсутствие полноценного результата не считалось чистым scan;
- источники Aqua и DHI включены, внутренний lidofinance/vex-db пока disabled;
- dhi_policy.py отдельно загружает policy/dhi-exceptions.json — это исключения из требования DHI base images, не CVE VEX.

Для нашего PR перенят стиль: тонкие YAML callers, reusable execution, обычные stdlib Python-модули, SHA pins,
сканирование отдельно от policy verdict. Штатный Trivy resolver не является библиотекой для Socket findings,
поэтому Trivy-specific helper не копируется и не импортируется. Его repository.yaml также не доказывает нужный нам порядок own → DHI → Aqua.
Для image/release интеграции целесообразно переиспользовать сам Trivy image gate после согласования PR 28.

## Организационные Rulesets

Схема без Socket GitHub App:

1. Поместить доверенный trigger workflow и helper/action в центральный репозиторий организации.
2. Добавить pull_request; при merge queue — также merge_group. Один workflow_call без PR trigger недостаточен для ruleset workflow.
3. Брать tooling из доверенного центрального ref; отдельно checkout целевого PR. Обычный checkout в caller context получает caller repo, а не автоматически центральные scripts.
4. Раздать Socket API token через organization secret с доступом только к выбранным репозиториям; contents:read достаточно для наших операций.
   Fork PR обычно не получает secrets — этот случай требует отдельной политики. Не запускать untrusted PR code с секретами через pull_request_target ради обхода ограничения.
5. Org Settings → Repository → Rulesets → New branch ruleset; выбрать репозитории и целевые ветки.
6. При доступности правила Require workflows to pass before merging выбрать центральный workflow/ref.
   Для неблокирующего rollout использовать Evaluate; Active делает красный job обязательным gate.
7. Если required workflows недоступны на плане, использовать thin caller в каждом repo и org rule Require status checks с точным именем job.
   Одно требование status check не устанавливает workflow автоматически.

Ruleset сам не сканирует и не выдаёт secret. Фильтры branches/paths/types у ruleset workflows игнорируются:
реальную область действия задаёт ruleset. Для такого централизованного workflow нужно убрать cancel-in-progress concurrency.
Нынешний PR — локальный POC caller, не готовая публикация в lidofinance/actions. Rulesets в организациях не менялись.

[GitHub required workflows](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets),
[troubleshooting](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules).

## Что означают генерация манифестов и shallow rescan

Генерация манифестов нужна, когда зависимости определяются исполняемой логикой build tool.
Например, Gradle build.gradle выбирает зависимости в зависимости от plugins, profiles и subprojects.
Socket запускает локальный build tool для разрешения графа и записывает результат в Socket facts / поддерживаемый манифест.
Этот результат затем анализируется обычным scan. Это не обязательно production build и не full application reachability.
Для Voting с package.json + yarn.lock такой генератор в текущем POC не требуется.

Shallow rescan не читает свежую ветку GitHub и не заново собирает приложение.
Пример: вчера сохранён scan S с lodash 4.17.11; сегодня изменена политика Warn → Monitor.
Shallow rescan создаёт новый scan на основе прежнего разрешённого графа и применяет актуальную политику.
Если в репозитории lodash уже обновлён до другой версии, shallow rescan S этого не обнаружит:
для нового состояния нужно загрузить новые manifests. Deep rescan повторяет разрешение зависимостей исходного scan;
он также не равен checkout последнего коммита GitHub.

[Generated manifests](https://docs.socket.dev/docs/socket-manifest), [Rescan API](https://docs.socket.dev/reference/rescanorgfullscan).

## Проверки и история

Текущие контрактные тесты находятся отдельно в socket-poc-lab/.github/scripts/test_socket_current.py:
24 теста, включая восемь центральных priority cases, Monitor-green, fallback, API retries, ошибки и VEX scopes.
Artifacts: report.json, findings.json, scan-artifacts.json, summary.md; для VEX — provenance, для baseline — проверка head.
Исторические результаты 09.11.2026 с красным Monitor сохранены как история старой политики;
текущая политика определяется этим документом и новым кодом. Последние Actions run links фиксируются в описании PR.

## Живая проверка обновлённой интеграции

На commit efb36df выполнены PR jobs и ручной develop-запуск:

- Native CLI job: success, без Python verdict.
- Server policy и VEX: verification_complete=true, 1433 компонента, 53 Warn, 1050 Monitor, 383 Ignore, exit 1.
- Develop baseline: head matches=true, 1433 компонента, 53 Warn, exit 1.
- Develop reachability: 1433 компонента, 35 Warn, 1068 Monitor, 383 Ignore; глобального fallback нет, errors=[]; exit 1 из-за Warn.

[PR native/policy comparison run](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42769069044),
[develop baseline/reachability run](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42769122259).
После этого native перенесён в отдельный workflow, чтобы его зелёный статус был виден на уровне всего workflow.
Fallback и инфраструктурные отказы проверены контролируемыми тестами; в живом reachability-запуске отказа не было.
Runtime scripts сокращены с 731 до 559 строк; lockfile инструмента не менялся.
