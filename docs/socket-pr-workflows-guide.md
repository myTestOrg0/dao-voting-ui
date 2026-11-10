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
- `socket-develop-baseline.yaml`: один develop reachability scan с fallback и публикацией основного dashboard report.
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

При успехе dashboard получает результат reachability; при глобальном отказе анализатора — обычный SCA fallback.
Новый основной scan проверяется через `default_branch=develop` и совпадение `head_full_scan_id`.
Для этого нужен Socket `repo:list`: чтение metadata, не GitHub write.
PR scans сохраняют `--no-set-as-alerts-page`, чтобы не заменять основной отчёт develop.

В workflow нет явного yarn build / Docker build. Engine может скачивать анализаторы и зависимости;
для некоторых экосистем нужен build toolchain. CLI закреплён хешами; версия engine 15.14.1 выбрана отдельно.
При fallback JSON `reachabilityFallback` сохраняется в report.json. Это не означает, что full application analysis выполнен.
Fallback с Warn/Block даёт 1; только Monitor — 0. Ошибка API или неполные данные дают 2.
Чтение API повторяется до трёх раз при временных сетевых/5xx/429 ошибках; 401/403 не повторяются.
Создание scan автоматически не повторяется, чтобы не создавать дубликаты неидемпотентным запросом.

Summary имеет отдельные разделы Findings, Reachability and fallback, Infrastructure and verification errors.
Если настройка runner/установка CLI не завершились, общий workflow также сохраняет сообщение о неполной проверке.
Unknown/missing_support отдельной CVE не равнозначны глобальному падению процесса.

После merge workflow запускается при push в develop. До merge: Actions → Socket native CLI PR → Run workflow
→ socket-pr-analysis → run_develop_checks=true. Этот ручной режим вызывает тот же develop workflow.

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
GitHub GITHUB_TOKEN остаётся contents:read; результаты jobs публикует сама платформа Actions, Socket App не устанавливается.
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
25 тестов, включая восемь центральных priority cases, Monitor-green, fallback, API retries, ошибки и VEX scopes.
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
