# Socket POC

## Поведение проверок

| Результат | Native CLI | Наша server-policy проверка | VEX проверка |
|---|---|---|---|
| Block | красный | красный | красный, если не снят применимым VEX |
| Warn | зелёный с отчётом | красный | красный, если не снят применимым VEX |
| Monitor | зелёный | зелёный; только счётчик и JSON artifacts | зелёный; только счётчик и JSON artifacts |
| Ignore | зелёный | зелёный | VEX рассматривается независимо от native Resolutions |
| Неполные данные / инфраструктурный сбой | штатный ненулевой CLI exit | код 2 | код 2 |

Severity CVE и action политики — разные поля. Critical CVE с Monitor не делает нашу проверку красной.
Коды нашей обвязки: 0 — нет Block/Warn; 1 — есть Block/Warn; 2 — проверка не завершена.
Коды самого Socket CLI не имеют такого строгого разделения: его 1 может означать как policy Block, так и ошибку исполнения.

Все jobs пока необязательны для merge. Их красный статус не запрещает merge, пока GitHub rulesets/required checks не требуют их прохождения.
`continue-on-error` не используется. Исходный `.github/workflows/socket.yaml` не изменён.

## Workflow и файлы

Все команды установки, запуска Socket и скачивания результатов видны непосредственно в workflow.
Общего reusable workflow и отдельного install-скрипта больше нет.

| Файл | Назначение |
|---|---|
| `native-pr-socket.yaml` | Native Node comparison case: автоматический PR scan, Summary и PR-комментарий через gh |
| `native-python-pr-socket.yaml` | Native Python test case: встроенный PR-комментарий, --disable-ignore и full snapshot через пустой control baseline |
| `wrapped-pr-socket.yaml` | Ручной test case через workflow_dispatch: серверная policy и нативные исключения Socket; VEX не загружается |
| `wrapped-pr-socket-vex.yaml` | Ручной test case через workflow_dispatch: наша обработка центрального VEX |
| `wrapped-baseline-socket.yaml` | Push develop и ручной запуск: reachability с fallback, публикация baseline |
| `.github/scripts/wrapped_report.py` | Разбор скачанного JSON, таблицы Summary и итоговый exit code |
| `.github/scripts/wrapped_vex.py` | Сопоставление продукта/версии/CVE и выбор VEX statement |
| `.github/scripts/wrapped_vex_sources.py` | Чтение уже скачанных VEX JSON; без сети и запуска Git |
| `.github/tools/socket-cli.lock` | Socket 1.13.1 и транзитивные зависимости с integrity hashes |
| `.github/socket-vex-sources.json` | Идентификатор продукта, источники и refs VEX |

Префиксы `native` / `wrapped` отличают штатный verdict от нашей логики.
`pr` означает pull_request; `baseline` — push в develop. Все пять workflow допускают ручной запуск.
Исходный socket.yaml сохранён без изменений.

Установка — обычные Bash-команды: sha256sum проверяет lockfile, jq извлекает package.json,
cp копирует lockfile, npm ci проверяет SHA-512 каждой зависимости. npm lifecycle scripts отключены.
Lockfile машинный, его не нужно читать как программную логику. Имя socket-cli.lock намеренно не совпадает с манифестами package manager: иначе автообнаружение Socket добавит зависимости CLI в scan приложения. Для npm он копируется в package-lock.json только вне scan target.

Скачивание результатов — явный curl с Basic auth и ограниченными retries.
Скачивание VEX — явный git clone с выбранной веткой и записью commit SHA.
Python не запускает внешние команды и не получает API secret: он обрабатывает только готовые файлы.
Маленький режим wrapped_report.py scan-id извлекает scan ID: CLI даже с --json может печатать progress перед JSON,
поэтому обычный jq на всём stdout ненадёжен.

## Нативный запуск

Job в native-pr-socket.yaml запускает напрямую:

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

## Один develop scan с reachability и fallback

Для develop выполняется ровно один job: `--reach --reach-fallback-to-regular-scan`.
Отдельный manifest-only baseline job удалён. Baseline означает роль результата как основного отчёта dashboard,
а reachability — способ анализа; это совместимые свойства одного scan, не два запуска.

Job сканирует отдельный настоящий checkout develop. Точный SHA читается внутри checkout.
Tooling находится в соседнем checkout и не попадает в scan target.
В одном вызове CLI используются:

```sh
--branch develop --default-branch --set-as-alerts-page \
--reach --reach-version 15.14.1 --reach-disable-analytics \
--reach-analysis-timeout 5m --reach-analysis-memory-limit 4GB \
--reach-fallback-to-regular-scan
```

При успехе CLI публикует reachability scan типа `socket_tier1` с запросом head; при глобальном отказе анализатора — обычный SCA fallback типа `socket`.
Repository API `head_full_scan_id` отражает legacy `socket` head. Поэтому для fallback проверяется его совпадение,
а при отличающемся reachability ID проверяются scan_type, branch и commit через scan metadata.
Активный typed head этим API не подтверждается: это явно записывается в Summary и baseline-head.json как matches=null,
а не выдаётся за успешное сравнение. Несовпадение ID разных scan types само по себе не считается инфраструктурной ошибкой.
Для этого нужен Socket `repo:list`: чтение metadata, не GitHub write.
PR scans сохраняют `--no-set-as-alerts-page`, чтобы не заменять основной отчёт develop.

В workflow нет явного yarn build / Docker build. Engine может скачивать анализаторы и зависимости;
для некоторых экосистем нужен build toolchain. CLI закреплён хешами; версия engine 15.14.1 выбрана отдельно.
При fallback JSON `reachabilityFallback` сохраняется в report.json. Это не означает, что full application analysis выполнен.
Fallback с Warn/Block даёт 1; только Monitor — 0. Ошибка API или неполные данные дают 2.
Чтение API повторяется до трёх раз при временных сетевых/5xx/429 ошибках; 401/403 не повторяются.
Создание scan автоматически не повторяется, чтобы не создавать дубликаты неидемпотентным запросом.

Summary имеет отдельные разделы Findings, Reachability and fallback, Infrastructure and verification errors.
Если настройка runner/установка CLI не завершились, workflow сохраняет сообщение о неполной проверке.
Unknown/missing_support отдельной CVE не равнозначны глобальному падению процесса.

После merge wrapped-baseline-socket.yaml запускается при push в develop и через Run workflow.
До merge новый filename может быть недоступен для workflow_dispatch; контрольный запуск проводят в отдельной lab-ветке через уже зарегистрированный workflow, без добавления proxy в native PR workflow.

Без `--reach` это не только сравнение версий с CVE-базой: Socket также использует сведения о malware,
supply-chain поведении пакетов, лицензиях и доступных серверных dependency/precomputed reachability результатах.
Отличие `--reach`: локально анализируется ещё и код нашего приложения. Manifest scan не является SAST приложения.

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

## Организационные Rulesets и расположение файлов

Предлагаемая структура центрального `lidofinance/actions`:

```text
.github/workflows/socket-pr.yml          # on: pull_request и merge_group; источник для Org Ruleset
.github/actions/socket-scan/action.yml   # trusted composite action
.github/actions/socket-scan/*.py         # helpers, installer и lock инструмента
```

Эти файлы ещё не опубликованы в lidofinance/actions. Нынешний PR остаётся POC в myTestOrg0/dao-voting-ui.

Центральный workflow получает событие целевого application repo. Обычный actions/checkout скачивает целевой repo,
а не автоматически файлы из actions. Поэтому он вызывает composite action полным путём
`lidofinance/actions/.github/actions/socket-scan@<reviewed-full-SHA>`; helpers доступны через github.action_path.
Это устраняет необходимость копировать скрипты в каждое приложение и отделяет доверенный tooling от PR content.
Просто `uses: ./.github/actions/socket-scan` после checkout целевого repo не означает обращение к центральному action.

Organization secret SOCKET_SECURITY_API_KEY должен быть доступен целевым application repos.
Secret, созданный только в actions repo, сам по себе не передаётся во все приложения.
Socket API token должен иметь доступ к соответствующим Socket repositories; для native report нужны create/list scans и чтение policy.
Без PR-комментариев достаточно contents:read; для выбранного native comment mode добавляется pull-requests:write. Socket App не устанавливается.
Для fork PR secrets обычно недоступны — нужна отдельная политика, а не выполнение непроверенного кода с secrets через pull_request_target.

Настройка: Org Settings → Repository → Rulesets → New branch ruleset; выбрать repositories и защищаемые branches,
затем Require workflows to pass before merging и указать source repo, защищённую ветку main и socket-pr.yml.
Для неблокирующего rollout — Evaluate; для обязательного gate — Active.
Одного workflow_call недостаточно: source workflow должен иметь поддерживаемый PR/merge_group trigger.
Фильтры branches/paths/types ruleset workflow игнорируются: область действия задаёт ruleset.
Для централизованного ruleset workflow нужно убрать cancel-in-progress concurrency.
При недоступности required workflows на плане нужны thin callers в приложениях и Require status checks.
Само требование status check workflow не устанавливает.

[GitHub required workflows](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets),
[troubleshooting](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules).

Полная инвентаризация действующих org rulesets текущему gh недоступна: REST/GraphQL требуют admin:org,
а пользователь является member и имеет read:org/repo/workflow. Права не расширялись.
Доступные унаследованные rulesets прочитаны через repository Metadata-read endpoints.
Локальный полный отчёт доступной выборки хранится отдельно в socket-poc-lab; приватные имена и policy metadata в публичный PR не публикуются.
Repository-level rulesets, classic branch protection и organization rulesets — разные сущности.

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
31 тест, включая восемь центральных priority cases, Monitor-green, fallback, ошибки, VEX scopes, evidence links, изоляцию репозиториев и effective VEX.
Python API retry tests удалены вместе с Python HTTP-клиентом: HTTP теперь выполняет curl в workflow.
Artifacts: report.json, findings.json, scan-artifacts.json, summary.md; для VEX — provenance, для baseline — проверка head.
Исторические результаты 09.11.2026 с красным Monitor сохранены как история старой политики;
текущая политика определяется этим документом и новым кодом. Последние Actions run links фиксируются в описании PR.

## Предыдущая контрольная проверка SCA против reachability

На commit efb36df, до объединения develop jobs, выполнено контрольное сравнение:

- Native CLI job: success, без Python verdict.
- Server policy и VEX: verification_complete=true, 1433 компонента, 53 Warn, 1050 Monitor, 383 Ignore, exit 1.
- Develop baseline: head matches=true, 1433 компонента, 53 Warn, exit 1.
- Develop reachability: 1433 компонента, 35 Warn, 1068 Monitor, 383 Ignore; глобального fallback нет, errors=[]; exit 1 из-за Warn.

[PR native/policy comparison run](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42769069044),
[develop baseline/reachability run](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42769122259).
После этого native перенесён в отдельный workflow, чтобы его зелёный статус был виден на уровне всего workflow.
Fallback и инфраструктурные отказы проверены контролируемыми тестами; в живом reachability-запуске отказа не было.
Runtime scripts сокращены с 731 до 559 строк; lockfile инструмента не менялся.

## package.json и lockfile — фактическая проверка backend

[Run 42779393640](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42779393640) в отдельной ветке codex/socket-lockfile-probe,
Socket CLI 1.13.1, Yarn classic lockfile. Рабочий PR не содержит экспериментальные скрипты.

| package.json lodash | yarn.lock | Найденные версии | CVE-2019-10744 |
|---|---|---|---|
| 4.17.11 | 4.17.11 | 4.17.11 | есть |
| ^4.17.0 | 4.17.11 | 4.17.11 | есть |
| 4.17.21 | старый selector/4.17.11 | **4.17.11 и 4.17.21** | остаётся у 4.17.11 |
| 4.17.21 | согласованный 4.17.21 | 4.17.21 | этой CVE нет |
| 4.17.21 | отсутствует | 4.17.21 | этой CVE нет |

При согласованных файлах manifest задаёт требование/диапазон, lock фиксирует конкретное разрешение.
При противоречии в проверенном случае Socket не выбрал одну «главную» версию: сохранил обе.
Обновление package.json не скрыло уязвимую старую версию из lockfile.
Это наблюдение для конкретного Yarn v1 input, а не гарантия одного алгоритма для всех package managers.
Версия 4.17.21 здесь исправляет выбранную CVE; отсутствие любых других CVE этим тестом не утверждается.
Release build должен проверять согласованность lockfile immutable/frozen install; текущий Dockerfile Voting уже использует yarn --frozen-lockfile.

## Интеграция Socket в release относительно lidofinance/actions

Точка интеграции — reusable k8s-build-push-harbor workflow из PR 28.
После validate уже известен проверенный source_sha. Добавить отдельный socket job с needs:validate,
checkout именно source_sha и вызовом доверенного central Socket action.
Затем publish должен иметь needs:[validate,socket], если Socket становится обязательным release gate.
Сам скан source manifests не требует предварительной сборки приложения; reachability — дополнительный режим.

Предлагаемая последовательность:

```text
validate release/tag и source_sha
  → Socket source scan + policy/VEX verdict
  → Docker build с frozen dependencies
  → существующий Trivy scan final image + image VEX
  → registry login и push
  → зафиксировать digest и artifacts
```

Socket перед release полезен даже после PR: могли появиться новые CVE/malware сведения,
измениться policies или отозваться исключения; release также может идти из другого tag/commit.
Скан должен соответствовать точному source_sha, а не свежему develop.
Release scans используют отдельную branch/tag метку и не меняют develop dashboard head.
Политика fallback на обычный SCA должна быть явной; полный отказ API не должен выглядеть как отсутствие проблем.

Trivy нужен отдельно: в final image есть OS packages, runtime и другие слои, которых нет в package.json.
Полный SBOM нужно генерировать из final image/digest и сохранять с release.
Его можно дополнительно передать Socket в поддерживаемом CycloneDX/SPDX формате, но это не заменяет проверку OS/image coverage Trivy.
Наличие Dockerfile само по себе не даёт полный перечень пакетов готового image.
Продакшен workflow в lidofinance/actions пока не менялся и релиз/публикация не запускались.

## Отложенный тест VEX на реальном DHI image

Пользователь отложил registry credentials и реальный image-тест. Pull dhi.io/python:3.13 получил Unauthorized.
Нужны read/pull secrets DHI_REGISTRY_USERNAME и DHI_REGISTRY_TOKEN либо доступное зеркало.
Поэтому ни выбранный vendor источник, ни изменение exit code на настоящем DHI image в этом обновлении не заявляются как измеренные результаты.

План использует те же pinned Trivy image и trusted helper из lidofinance/actions PR 28:
загрузить image один раз, зафиксировать digest/platform, выполнить raw image scan,
заморозить версии Trivy DB и трёх VEX источников и сравнить решения.
Для suppressed findings Trivy 0.62.1 сохраняет ModifiedFindings со Status, Statement и Source.
Для неснятых findings это не полный decision ledger, поэтому matched-but-affected решения нужно фиксировать отдельно.

Существенное отличие закреплённой версии: RepositorySet.NotAffected в Trivy 0.62.1 прекращает поиск
после первого совпавшего package index entry, даже если документ не содержит matching statement для текущей CVE.
Наш Socket matcher переходит к следующему источнику при отсутствии statement для конкретной package/version/CVE.
Поэтому простой порядок own → DHI → Aqua в repository.yaml не доказывает эквивалентность алгоритмов.
[Trivy 0.62.1 repo resolver](https://github.com/aquasecurity/trivy/blob/v0.62.1/pkg/vex/repo.go#L70-L113).

Для строгой единой семантики потребуется либо заранее собрать effective VEX с приоритетом на уровне точного продукта/CVE,
либо выбрать и проверить версию/режим resolver, соответствующие нашей матрице. Ни один вариант не следует объявлять проверенным без image test.
Контрольная матрица: own affected против DHI not_affected; own not_affected против DHI affected;
нет подходящего own → DHI; нет own/DHI → Aqua; wrong digest/arch/version; отзыв own;
полный image gate против одной изолированной finding. Реальное существование finding/CVE подтверждается raw scan,
контрольный собственный statement явно помечается test-only и не публикуется как производственное заключение неприменимости.


## Ссылка на репозиторий и обоснование в OpenVEX

Да. Стандартный statement `@id` может быть URL конкретного документа/раздела;
`status_notes` допускает пояснения и ссылки на материалы анализа. Например, фрагмент statement:

```json
{
  "@id": "https://github.com/ORG/vexel/blob/COMMIT/pkg/npm/PACKAGE/vex.json#statement-id",
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "status_notes": "Evidence: https://github.com/ORG/APP/blob/COMMIT/docs/security/CVE-analysis.md"
}
```

Это фрагмент: для полноценного statement также требуются vulnerability и products.
Пример не означает, что какая-либо CVE уже признана неприменимой.
Ссылка на immutable commit лучше ссылки на изменяемую ветку.
URL не задаёт область применимости: она определяется products / subcomponents и точным сопоставлением пакета/версии/CVE.
Один URL не заменяет justification или impact_statement.

Наш Summary теперь показывает ссылку на фактически использованный VEX JSON в конкретном commit.
findings.json также сохраняет statement_id и status_notes; vex-provenance.json — URL, commit и хеш документа.
Ссылки из текста status_notes сохраняются как обоснование, не исполняются и не скачиваются автоматически.
[OpenVEX statement fields](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#statement-fields).


## Исключения только для указанных репозиториев

В собственном OpenVEX products задаёт точный URL каждого разрешённого application repository.
Внутри каждого продукта subcomponents содержит точный PURL зависимости с версией:

```json
"products": [
  {
    "@id": "https://github.com/myTestOrg0/dao-voting-ui",
    "subcomponents": [{"@id": "pkg:npm/lodash@4.17.11"}]
  },
  {
    "@id": "https://github.com/myTestOrg0/another-approved-repo",
    "subcomponents": [{"@id": "pkg:npm/lodash@4.17.11"}]
  }
]
```

Это пример scope, не реальное утверждение неприменимости. Текущие own statements остаются under_investigation.
Обвязка получает текущий owner/repo из GITHUB_REPOSITORY, а не из переносимого product_id в конфигурации.
Собственный statement без совпавшего repository product, в том числе один bare package PURL,
не снимает finding. Wildcards не поддерживаются. Другой owner с тем же repo name не совпадает.
Одновременно должны совпасть repository, package/version и CVE/GHSA.

Если заявление нужно для нескольких репозиториев, каждый перечисляется в products со своим subcomponents.
Утверждение об использовании одной версии пакета в приложении не доказывает, что одинаковое исключение применимо в другом приложении.
Текущий product scope привязан к repository в целом; для branch/release/digest потребуются отдельные точные product identifiers.

## Effective VEX

Общая логика выбора находится в существующем wrapped_vex.py, без нового скрипта или workflow.
Сначала проверяется применимость источника к типу продукта, затем repository/component/version/CVE,
затем берётся первый matching statement по own → DHI → Aqua.
Отсутствие matching statement позволяет проверить следующий источник; affected/under_investigation его останавливают.

После выбора формируется artifact effective-vex.json: только выбранные statements и только текущий repository product.
В нём сохраняются исходные статусы и ссылки на источники; timestamps собственных statements наследуются из исходного документа.
Находки без подходящего VEX сохраняют policy action и не превращаются в выдуманные not_affected statements.
Если ничего не подошло, OpenVEX с пустым statements не создаётся: официальный JSON Schema требует хотя бы один statement.
Наш exit code рассчитывается по тем же выбранным решениям; effective-vex.json не является вторым независимым resolver.

Для application scan сейчас работает только own. Полная цепочка трёх image-источников остаётся контролируемым тестом;
реальный DHI image run отложен. Image output должен дополнительно совпадать с digest/platform,
прежде чем передавать его Trivy как единственный заранее разрешённый VEX.

Гарантию изоляции обеспечивает наш matcher. Не каждый сторонний OpenVEX consumer сопоставляет GitHub repository URL:
для него необходим такой же context-aware matcher либо предварительная фильтрация строго под текущий artifact.
Общий effective VEX для всех приложений выпускать не следует.

## SBOM и центральное хранение

Socket экспортирует результаты scan в CycloneDX или SPDX через API:
GET /v0/orgs/{org}/export/cdx/{scan_id} и /export/spdx/{scan_id}.
Оба endpoint помечены Beta, требуют report:read и расходуют квоту; неподдерживаемые ecosystems фильтруются.
[Socket CycloneDX export](https://docs.socket.dev/reference/exportcdx), [SPDX export](https://docs.socket.dev/reference/exportspdx).
В этом PR экспорт не включён и новые права токену не запрашиваются.

Рекомендуемая основа — централизованно хранить immutable SBOM каждого release artifact:
repository + source SHA + image digest + platform + generator/version + время создания.
Socket SBOM описывает найденный им application graph; final-image SBOM от Trivy дополняет его OS/runtime составом.
Raw SBOM, raw findings и effective VEX лучше сохранять раздельно, чтобы исключения не удаляли сведения о составе продукта.

Для POC достаточно Actions artifacts. Для долговременного хранения releases — существующий registry с поддержкой SBOM accessories/referrers
или object storage с контролируемой retention, доступом и индексом repo/version/digest.
Не нужно складывать все версии JSON в Git или объединять организацию в один SBOM.
Если понадобится поиск затронутых проектов и постоянная переоценка всей организации,
можно отдельно рассмотреть Dependency-Track; это не обязательный компонент текущего POC.


Серверные исключения и центральный VEX проверяются разными workflow, без matrix и вызовов друг друга.
В wrapped-pr-socket.yaml используется SOCKET_MODE=policy: действие сервера принимается как есть,
включая результат native Alert Resolutions; собственные VEX файлы не скачиваются и не применяются.
Наша обвязка здесь только формирует Summary и делает Block/Warn красными.
В wrapped-pr-socket-vex.yaml используется SOCKET_MODE=vex и отдельный VEX snapshot.
Concurrency groups и artifact names различаются, поэтому эти test cases не отменяют и не перезаписывают друг друга.


## Вывод Monitor и назначение wrapped report

Построчные Monitor не выводятся в Actions log и основную таблицу findings в Summary.
В Summary остаётся общий счётчик; findings.json и scan-artifacts.json сохраняют полные результаты.
Warn/Block по-прежнему выводятся и дают exit 1. Native CLI использует report-level warn и также не перечисляет Monitor.

Для native запуска используется собственный Markdown-отчёт CLI, без нашего renderer.
Для server-policy test case итог берётся из alert.action в API scan: это готовое действие сервера.
В исходниках закреплённого CLI 1.13.1 generateReport вместо этого выбирает
securityPolicy.securityPolicyRules[alert.type].action. Следовательно, вывод CLI нельзя автоматически
считать эквивалентом per-alert server decisions, включая native resolutions и другую серверную обработку.
В VEX test case нужен также итог после собственного resolver, которого штатный CLI не выполняет.
Поэтому wrapped report содержит сведения для наших двух test cases, а не копию штатного CLI report.
Сама форма Markdown не обязательна: полезная часть — выбранное server/effective action, CVE/package и итог gate.


## Контрольный тест CLI против server wrapper на native resolution — 10.11.2026

[Live Actions run 42810580540](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42810580540),
lab branch codex/socket-lockfile-probe, harness commit b30ae2e, Socket CLI 1.13.1 с проверенным integrity.
Все три scans созданы на одном application SHA 1b4f7806567184dc99e5ff74bc0010943bf654c0.
В каждой фазе CLI и wrapper получают одинаковый scan ID. Между фазами создаётся новый scan того же source SHA,
чтобы сервер применил создание/отзыв resolution. Ни один scan не заменяет develop dashboard baseline.

Реальная находка: lodash@4.17.11 / CVE-2019-10744, тип criticalCVE, действие org policy Warn.
Selector ограничен dao-voting-ui + npm + namespace="" + lodash + 4.17.11 + criticalCVE + этой CVE.
Причина other: временный тест интеграции, не утверждение о неприменимости уязвимости.
Политика не изменялась: hash полного securityPolicyRules одинаков во всех фазах.

| Фаза | Org policy | Серверное action | Находка в CLI report | CLI process exit | Wrapper process exit | Verdict только этой CVE |
|---|---|---|---|---:|---:|---:|
| До исключения | Warn | Warn / org-policy | Warn | 0 | 1 | 1 |
| Исключение активно | Warn | Ignore / resolution | **По-прежнему Warn** | 0 | 1 | **0** |
| Исключение отозвано | Warn | Warn / org-policy | Warn | 0 | 1 | 1 |

CLI запущен как socket scan report --report-level warn --license --json <scan_id> <output>.
Его process exit 0 во всех фазах не доказывает применение исключения: исходное действие Warn и так неблокирующее.
Полный wrapper остаётся с process exit 1 из-за других Warn. Последняя колонка — отдельный расчёт тем же verdict
на одной выбранной finding, а не process exit сканирования всего репозитория.
У lodash этой версии ровно один criticalCVE alert, поэтому строка CLI однозначно относится к целевой CVE,
хотя штатный CLI renderer группирует данные по типу алерта, а не выводит CVE ID.

Во всех фазах 1433 компонента; контрольные CVE-2020-8203 и CVE-2021-23337 остаются Warn.
Удаление созданного resolution подтверждено DELETE и последующим GET HTTP 404; cleanup выполняется также при ошибке.

Вывод для закреплённого CLI 1.13.1: native resolution применяется сервером, но не снимает finding из CLI policy report.
Серверную обвязку пока сохраняем. Результат относится к проверенному scan report path и этой версии CLI;
поведение других версий/интеграций и Block-исключений этим Warn-тестом не доказано.
Исходники теста и архив результатов оставлены вне application PR; в нём добавлена только эта запись в документации.


## Текущий native PR mode и комментарии

Автоматически на pull_request запускаются два native test cases: Node и Python. Оба wrapped workflow сохранены как ручные test cases.
Native использует один checkout точного PR head SHA, inline установку hash-pinned Node CLI 1.13.1 и прямую команду scan create --report.
Node CLI сам формирует Markdown и process exit; Python scripts в этом workflow не вызываются.
Warn показываются и не делают native policy verdict красным; Monitor не перечисляются.

К permissions добавлено только pull-requests:write поверх contents:read. GH_TOKEN передаётся шагу публикации комментария.
Готовый native Markdown копируется в Actions Summary и PR-комментарий с ссылкой на run и source SHA.
Через gh api ищется комментарий github-actions[bot] с маркером socket-native-report:
если он существует, выполняется PATCH; иначе POST. Чужие bot/user comments не перезаписываются.
Обработка @SocketSecurity ignore и issue_comment trigger не добавлены: публикация отчёта не включает suppression.
Код размещён прямо в workflow, без отдельного comment script, reusable workflow или стороннего commenting action.

POC запускается для PR из веток того же repository; fork PR пропускаются, поскольку обычный pull_request не получает Socket secret и write token.
Отдельный доверенный поток публикации для forks этим POC не реализуется; pull_request_target с исполнением PR кода не используется.
При ошибке CLI комментарий показывает failure и ссылку на Actions; отсутствие отчёта не выдаётся за чистый scan.
Ранее измеренное отличие native report от server actions сохраняется: комментарий публикует именно штатный результат CLI.

## Node CLI и Python CLI — разные инструменты

Сравнение относится к нашему Node CLI socket 1.13.1 и исследованному Python CLI socketsecurity 2.11.13,
source commit bb77908c9921f77ef6b8e0008a29937fe725811d. Main Node repository уже разрабатывает 2.x prerelease,
поэтому выводы о закреплённом 1.13.1 нельзя переносить на все новые версии.

| Свойство | Node CLI | Python CLI |
|---|---|---|
| Установка / команда | npm package socket / socket | PyPI package socketsecurity / socketcli; Python >=3.11 |
| Основной профиль | Набор команд scan, diff, package analysis, package-manager Firewall | CI/SCM orchestration: baseline, diff, PR comments, output formats |
| Языки проверяемого проекта | Поддерживаемые Socket ecosystems | Поддерживаемые Socket ecosystems; не только Python |
| Обычный PR flow | У нас full snapshot через scan create --report | Ориентирован на сравнение с baseline; доступен выбор base scan/commit |
| Действия алертов | В проверенном 1.13.1 report пересчитываются по policy[type] | Core переносит action из API в Issue flags |
| GitHub PR comments | В нашем workflow публикация готового Markdown через gh | Встроенная SCM integration с --scm github и --pr-number |
| Comment suppression | Наш workflow не читает ignore commands | Встроенная обработка ignore commands; отключается --disable-ignore |
| Вывод | У нас native Markdown и Summary | Console/JSON, SARIF, GitLab report и SCM comments |
| Reachability | --reach и используемый нами fallback flag | --reach через тот же класс Coana engine; есть собственные требования/flags |

В Python diff mode по умолчанию gate рассматривает новые Block/error alerts; Warn сами не дают exit 1.
--strict-blocking включает также unchanged Block findings в diff. Это не превращает Warn в Block.
При успешной проверке exit 0, blocking findings exit 1; API/runtime failures по умолчанию exit 3.
--disable-blocking принудительно даёт 0 даже при инфраструктурной ошибке, поэтому это не эквивалент optional required check.
Особенность исследованной Python версии: full-scan path без comparison автоматически отключает blocking;
--strict-blocking работает только в diff mode. Это важно перед заменой release/full-snapshot gate.
Native GitHub check можно оставить необязательным через rulesets, сохранив настоящий ненулевой exit при Block.

Серверные native resolutions и server-applied action Python читает другим путём, чем проверенный Node report.
Это подтверждено исходниками Core; end-to-end цикл native resolution именно с Python CLI здесь пока не проводился.
Свои raw OpenVEX feeds / приоритеты own→DHI→Aqua Python CLI автоматически не реализует: это отдельная задача интеграции.

## Может ли Python CLI подавлять находки в PR

Да, в SCM PR/diff flow он читает команды из PR discussion, например:

```text
@SocketSecurity ignore npm/lodash@4.17.11
@SocketSecurity ignore-all
```

Первый вариант фильтрует alerts указанного package/version в обрабатываемом PR наборе, а не одну конкретную CVE.
Версия * также поддерживается matcher; ignore-all ещё шире. Это локальное решение CLI по PR comments,
не создание Socket native resolution и не изменение OpenVEX или политики в dashboard.
На обычном PR scan matching new_alerts удаляются перед расчётом verdict: последний новый Block может исчезнуть и exit стать 0.
--strict-blocking отдельно проверяет unchanged alerts; comment filtering new_alerts не следует считать универсальным обходом всех findings.

CLI считывает комментарии при запуске. Автоматический запуск от нового комментария требует issue_comment workflow;
обычный pull_request trigger на комментарий не срабатывает. Comment-only flow может обновить текст отчёта без нового scan:
само появление ignore comment не переписывает результат старого Actions run.
Для возвращения finding удаляют/правят ignore comment и запускают проверку заново.

В 2.11.13 проверяются права автора команды: GitHub write/maintain/admin разрешены; read-only автор отклоняется.
--ignore-authorization=enforce по умолчанию допускает ignore с предупреждением, если права нельзя определить.
strict отклоняет команду при неопределённых правах; off отключает проверку автора.
Для нашего требования полного запрета comment suppression правильный параметр — --disable-ignore:
он выключает фильтрацию и скрывает инструкции ignore в генерируемых security comments.
Публикация PR comments при этом остаётся доступной. Флаг не отключает серверные native resolutions или policy Ignore.

SCM integration получает GitHub token через GH_API_TOKEN; Socket token — через SOCKET_SECURITY_API_KEY или SOCKET_SECURITY_API_TOKEN.
Для публикации комментариев нужен PR write; Socket GitHub App для CLI SCM integration не обязателен.
Исследованы [README](https://github.com/SocketDev/socket-python-cli),
[CLI reference](https://github.com/SocketDev/socket-python-cli/blob/bb77908c9921f77ef6b8e0008a29937fe725811d/docs/cli-reference.md),
[comment processing](https://github.com/SocketDev/socket-python-cli/blob/bb77908c9921f77ef6b8e0008a29937fe725811d/socketsecurity/core/scm_comments.py),
[exit handling](https://github.com/SocketDev/socket-python-cli/blob/bb77908c9921f77ef6b8e0008a29937fe725811d/socketsecurity/output.py).


## Native Python PR test case

Файл native-python-pr-socket.yaml — отдельный workflow с socketsecurity 2.11.13 / socketcli.
CLI и 19 dependencies закреплены версиями и SHA-256 в socket-python-cli.lock;
pip использует --require-hashes --only-binary=:all:. Lock рассчитан на CPython 3.12 / Linux x86_64.
Новых Python helper scripts в application PR не добавлено: команды видны в YAML.

Последовательность:

1. Checkout точного PR head с полной историей.
2. Установка проверенного CLI.
3. Native API-mode scan синтетического package.json без dependencies во временной папке runner.
   Его отдельная branch native-python-control-<run_id> не является develop и не меняет dashboard baseline.
4. Native SCM comparison настоящего snapshot PR с этим контрольным пустым scan.
5. Сам Python CLI создаёт или обновляет свой security PR comment. Summary/JSON сохраняются как artifacts.

Пустой control baseline выбран намеренно: POC проверяет весь snapshot, а SCM-комментарий Python CLI 2.11.13
строится из new_alerts. --strict-blocking расширяет gate/JSON на unchanged, но сам по себе не включает их в native SCM comment.
С контрольным baseline реальные находки snapshot попадают в new_alerts и видны в PR.
Это не обычный diff с develop; для production net-new проверки control baseline нужно заменить реальным base scan.

Основные параметры:

- --scm github: встроенный GitHub adapter, а не печать Markdown для последующего gh.
- --repo: Socket repository slug dao-voting-ui; --owner: integration owner myTestOrg0.
- --base-scan-id: ID только что созданного control scan.
- --ignore-commit-files: не пропускать сравнение, если изменён только workflow, а не dependency files.
- --strict-blocking: учитывать unchanged Block findings при diff gating; Warn не становится Block.
- --disable-ignore: полностью выключить suppression по PR comments, включая ignore-all.
- --disable-overview: не создавать второй dependency-overview comment.
- --json-file / --summary-file / --report-link-file: штатные CLI artifacts, без собственного renderer.

Обычный native-python workflow не создаёт и не удаляет resolutions; эти операции выполняются только в отдельной lab-проверке.
GitHub token имеет contents:read и pull-requests:write. Socket API token и GitHub token — разные credentials.

[Первый native-python run](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42839755924) прошёл успешно
и сам опубликовал [PR comment](https://github.com/myTestOrg0/dao-voting-ui/pull/2#issuecomment-6770725958).
В JSON есть lodash@4.17.11 / CVE-2019-10744 с Warn. Один CVE может иметь несколько instances;
число JSON rows нельзя напрямую приравнивать к количеству уникальных уязвимостей.

Текущий токен не имеет прав на новый diff-scans API: Python CLI явно логирует Insufficient permissions
и успешно выполняет legacy streaming comparison. Это завершённый fallback, не --disable-blocking.
Для нового API документация клиента указывает diff-scans:create/list и full-scans:list.

### Native resolution lifecycle: состояние проверки

[До исключения](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42841125274):
1433 компонента, criticalCVE policy Warn, server action Warn, native Python target Warn, process exit 0.
Две control CVE остаются Warn; --disable-ignore включён, native security comment обновлён.

Создание исключения пока заблокировано: POST alerts/resolutions?dry_run=true вернул HTTP 403
с details.requiredScopes=["alert-resolution:create"].
[Read-only/dry-run probe](https://github.com/myTestOrg0/dao-voting-ui/actions/runs/42842082330)
подтвердил этот ответ для short и fully qualified repo selector.
В этой попытке POST без dry_run не выполнялся; постоянный resolution не создавался.
После выдачи разрешения требуется завершить active/revoked phases; результат Python native suppression до этого не заявляется доказанным.

## Нативная публикация комментариев и выбор CLI

Python CLI имеет встроенный SCM adapter, который вызывает GitHub API создания/редактирования comments.
Node CLI 1.13.1 scan create --report формирует Markdown; в нашем workflow публикацию выполняет gh.
Сам --pull-request задаёт metadata scan и не является включением GitHub comment posting.
Команда Node scan github скачивает manifests default branch через GitHub API; это также не PR-comment publisher.

Практическое разделение documented roles: Node — универсальные API/package/developer tools и Firewall/manifest commands;
Python — CI/SCM orchestration, scan diff, built-in comments и интеграционные output formats.
Оба работают с Socket backend и поддерживаемыми ecosystems, а не только с языком своей реализации.

Для наших PR-требований Python — предпочтительный кандидат: меньше собственного glue code и используются per-alert API actions.
Окончательную замену server wrapper нужно принимать после полного native resolution lifecycle test.
Node остаётся полезен для package analysis, install-time Firewall и генерации manifests.
Release gate требует отдельной валидации: Python full-scan path без comparison автоматически не блокирует findings.
