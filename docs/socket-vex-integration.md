# Socket POC: PR report and VEX integration design

Проверено 6 ноября 2026. VEX-фильтрация в PR workflow пока **не включена**.

## Что делает PR workflow

`.github/workflows/socket-pr-test.yaml` сканирует весь checkout PR, а не diff зависимостей.
Socket CLI `1.13.1` сам рекурсивно обнаруживает поддерживаемые manifest/lock-файлы;
список package.json/yarn.lock не задаётся. Действуют правила исключения CLI и проекта.
Зависимости приложения не устанавливаются. Устанавливается только сам Socket CLI.
Имена Socket organization/repository берутся из Actions variables `SOCKET_ORG` и
`SOCKET_REPO`; значения по умолчанию — `lido-labs` и имя GitHub repository.

GitHub token имеет только `contents: read`. Summary записывается в
`GITHUB_STEP_SUMMARY`: PR → Checks → Socket dependency scan → Summary.
Комментарий в обсуждении PR не создаётся. Команды подавления в комментариях не читаются.
Артефакт `socket-report` хранится 7 дней и содержит Markdown, CLI report, сгруппированные
находки и исходные записи скана. Token и захваченные CLI-логи в артефакт не включаются.

CLI только создаёт скан (без `--report`). Следующий шаг читает серверные `alert.action`:
`error`/Block → exit 1; Warn/Monitor/Ignore → exit 0; неизвестное действие → exit 2. Ошибки API или
невозможность получить отчёт завершают проверку ошибкой, а не успешным «0 findings».
Summary строится по текущему scan ID и показывает package/version, CVE/GHSA, severity,
действие и первую исправленную версию, если она известна. Счётчики дедуплицируются по
экосистеме, package/version и advisory. Это не число уникальных CVE организации.
Monitor/Ignore сохраняются в JSON. Для forks GitHub обычно не выдаёт repository secret:
такой запуск не сможет сканировать и не должен считаться чистым.

Native report CLI 1.13.1 повторно вычисляет действие по типу алерта, поэтому он
больше не участвует в gating. И Summary, и итоговый статус используют серверные
действия одного скана. Например, сервер вернул Monitor из precomputed reachability
для critical advisory у elliptic 6.5.4, хотя native CLI report давал Warn.
`report.json` теперь содержит серверный verdict и исходный результат создания скана.

Документация: [Socket scan](https://docs.socket.dev/docs/socket-scan),
[GitHub job summary](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-job-summary).

## Проверка разрешений Actions

В [myTestOrg0/actions](https://github.com/myTestOrg0/actions):

| Файл | Явные permissions | Назначение записи |
|---|---|---|
| `.github/workflows/prepare-release-draft.yml` | `contents: write` | `gh release create/edit --draft` |
| `.github/workflows/ci-ipfs.yml` | `contents: write` | публикация release/assets через composite action |
| `.github/workflows/k8s-build-push-harbor.yml` | `contents: read` | сборка/публикация в registry, отдельные credentials |
| `.github/workflows/ci-ens.yml` | не заданы | наследование caller/default; вывод в job summary |
| `.github/workflows/k8s-validate-helmcharts.yml` | не заданы | наследование caller/default |

В двух release workflows `pull-requests: write` не задано: при явном permissions
неуказанные категории получают `none`. `contents: write` даёт запись в Releases,
но не разрешение публиковать PR review/comment через PR API. Для обычного issue-comment
на PR используется соответствующее GitHub API permission (`issues`/`pull-requests`);
эти категории здесь не выданы. Composite action `ipfs-release` вызывает `gh release`,
а `create-summary: true` у changelog action относится к Actions Summary.
Reusable workflow не может повысить permissions полученного GITHUB_TOKEN.
Несколько actions вызываются из `lidofinance/actions@main`, а не из локального форка:
для воспроизводимого аудита их следует закрепить на commit SHA.

Отдельно: исходный `.github/workflows/socket.yaml` в Voting **уже имеет**
`issues: write` и `pull-requests: write` в job `socket-security`, trigger —
`workflow_dispatch`. Он не изменён. Эти права не переходят в новый PR workflow.

## Источники VEX и приоритет

OpenVEX — формат утверждений о применимости конкретной уязвимости к продукту;
это не самостоятельная база обнаружения CVE. Статусы: `affected`, `not_affected`,
`fixed`, `under_investigation`.
[Спецификация](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

Согласованный приоритет:

1. [myTestOrg0/vexel](https://github.com/myTestOrg0/vexel) — собственные решения.
2. [Docker Hardened Images advisories](https://github.com/docker-hardened-images/advisories).
3. [Aqua Security VEX Hub](https://github.com/aquasecurity/vexhub).

Все три репозитория публикуют `vex-repository.json` версии specification 0.1.
У собственного feed update interval 24h, у Docker 1h, у Aqua 24h.
Собственный feed называется `dhi-python-3.13-local-vex`: сейчас это Debian/DHI Python.
Например, `pkg/deb/debian/libexpat1/vex.json` содержит `affected` для
`CVE-2025-66382`, package `2.8.3-1~deb13u1+dhi2`, arch arm64, distro debian-13.6.
Voting использует `node:20-alpine`, а Socket PR scan анализирует npm manifests.
Такое Debian-утверждение нельзя переносить на npm/Alpine только по совпадению CVE.
Для демонстрации VEX в Voting нужна собственная запись для реально найденного npm
package/version с обоснованием; отдельный DHI image scan нужен для демонстрации Docker feed.

## Что поддерживается нативно

Trivy умеет подключать VEX repositories в порядке приоритета:

```yaml
repositories:
  - name: own
    url: https://github.com/myTestOrg0/vexel
    enabled: true
  - name: docker-dhi
    url: https://github.com/docker-hardened-images/advisories
    enabled: true
  - name: aqua
    url: https://github.com/aquasecurity/vexhub
    enabled: true
```

Это конфигурация VEX repository Trivy, не Socket. Запуск image scan:
`trivy image --vex repo --show-suppressed IMAGE@sha256:DIGEST`.
Документация описывает остановку поиска на первом подходящем VEX-документе по PURL;
поэтому fallback для неполного собственного документа нужно проверить отдельно на
выбранной версии Trivy. Порядок источников не равен гарантированному merge всех CVE.
[Trivy priority](https://trivy.dev/docs/latest/supply-chain/vex/repo/#repository-priority),
[Docker scanning](https://docs.docker.com/dhi/how-to/scan/).

У Socket подтверждён [OpenVEX export API](https://docs.socket.dev/reference/exportopenvex).
Публично документированного импорта этих трёх external VEX repositories для `socket
scan create` не найдено. Экспорт Socket не является импортом внешних решений.
Socket [alert resolutions](https://docs.socket.dev/docs/alert-resolutions) — отдельный
механизм, который меняет последующие результаты в dashboard и имеет приоритет над policy.

## Предлагаемое рабочее решение для Socket

Следующий этап — отдельный CI adapter после получения исходного Socket scan. На первом этапе
он только добавляет колонки VEX status/source/reason в Summary, не меняя gating.
Следующим этапом, после проверки fixtures, он может рассчитывать effective verdict.
Создание scan, ошибки инфраструктуры и решение effective policy уже разделены.
Для применения VEX нужно расширить текущую server-action evaluation до effective policy.
Ошибки скана не должны превращаться в non-blocking policy findings.

Правила adapter:

- Нормализовать finding в ecosystem + namespace/name + exact version + CVE/GHSA aliases.
  Для image findings дополнительно сохранить digest, distro и architecture.
- Для каждого finding искать **применимое утверждение**, а не любой файл пакета,
  в порядке own → Docker → Aqua. Учитывать product/subcomponent scope и PURL qualifiers.
  Не пытаться сопоставлять Debian/Alpine/npm по одному имени.
- Выигрывает первое применимое утверждение высокого приоритета. `affected` и
  `under_investigation` сохраняют finding; низкий `not_affected` их не отменяет.
  Для `not_affected` нужно обоснование/impact statement; `fixed` должен относиться
  к точному поставляемому продукту. Отсутствие записи или неоднозначность — не исключение.
- Конфликтующие записи одного источника, неверный формат, недоступный/просроченный feed:
  не подавлять finding; выводить статус неполной проверки.
- Сохранять raw и effective findings, выбранное утверждение, причину, source URL,
  commit/hash документа и время загрузки. Фиксировать снимки источников на запуск,
  чтобы PR и release можно было воспроизвести. Срок пересмотра собственных решений
  хранить как локальную metadata, поскольку стандарт OpenVEX не задаёт универсальный expiry.
- Доверенный список feed и правила приоритета брать из защищённой конфигурации;
  не позволять тому же PR без отдельного review добавить себе исключение.

Такой adapter не меняет Socket dashboard: применимость видна в CI Summary и artifacts.
Для синхронизации dashboard нужен отдельный контролируемый процесс, который создаёт
узкие Socket resolutions (repo + ecosystem + package + version + CVE) и отзывает их
при удалении/смене VEX. Ему нужны отдельные write scopes Socket API, но GitHub App
не требуется. В PR scanner эти write scopes добавлять не нужно. Влияние resolutions на серверные actions конкретного scan нужно подтвердить
контрактным тестом; native CLI report в этой схеме не используется.

## Проверки для следующего этапа POC

1. Один и тот же package/version/CVE: own `affected` против Docker `not_affected` → finding остаётся.
2. Own `not_affected` с обоснованием против upstream `affected` → исключение с указанием own.
3. Own без данного CVE → fallback Docker, затем Aqua; отдельно сравнить поведение Trivy.
4. Другая версия, arch/distro, image digest или npm вместо Debian → исключение не применяется.
5. Нет VEX, конфликт/сломанный feed, under_investigation → finding остаётся видимым.
6. Отзыв исключения → finding возвращается; raw scan всегда доступен.
7. В release повторить scan текущего артефакта и VEX evaluation; проверить warning/block
   на одной и той же fixture, затем убедиться, что публикация зависит от effective verdict.


## Reachability и граница передачи данных

Текущий PR workflow запускается без `--reach`: передаются автоматически обнаруженные
поддерживаемые manifests/lockfiles (в проверенном скане package.json и yarn.lock).
Precomputed reachability анализирует известный публичный код зависимостей и пути
между пакетами; исходники Voting для этого не нужны. По документации Socket,
этот режим не определяет применимость CVE в прямой зависимости, предполагает отсутствие
phantom dependencies и может быть неполным при приватных пакетах.
[Precomputed reachability](https://docs.socket.dev/docs/precomputed-reachability).

Full application reachability (`--reach`) дополнительно анализирует код приложения
и зависимостей. CLI может запускать анализ на нашем runner; Socket предлагает также
managed scans на своей инфраструктуре. Для local mode исходный код можно оставить
на своей инфраструктуре, а результаты анализа/SBOM metadata отправлять Socket.
В metadata могут присутствовать имена файлов и сведения о вызовах: состав `.socket.facts.json`
нужно проверить перед включением. По текущей документации нужен Enterprise/trial,
Node 22+ и language toolchain. В POC full application mode не включён.
[Full application reachability](https://docs.socket.dev/docs/full-application-reachability).

## Центральное управление исключениями организации

VEX — формат обмена применимостью CVE, а не полная система управления исключениями.
Accepted risk не означает `not_affected`; исключение для лицензии, malware/typosquatting,
IaC или secret finding вообще не описывается обычным vulnerability VEX.
Обещать native поддержку одного файла всеми инструментами нельзя.

Рекомендуемая архитектура POC: защищённый central security-decisions Git repository
как source of truth + versioned evaluator в переиспользуемом CI workflow.
OpenVEX — один из входных и выходных форматов этого решения.
Это проект следующего этапа, новый registry/evaluator пока не реализован.

Собственная запись содержит: стабильный ID, scope (repo/product/component/version,
при необходимости image digest/distro/arch), CVE/GHSA или tool rule ID, тип решения,
обоснование и evidence, owner/approver, дату действия и обязательный срок пересмотра.
Разделяем технический статус (affected/not_affected/fixed/under_investigation)
и временное разрешение принять риск, которое может существовать при affected.

Последовательность gate:

1. Зафиксировать commit артефакта, digest image и версию центральной политики/исключений.
2. Собрать исходные findings Socket, Trivy и остальных scanner-ов. Ошибки scanners
   и неполное покрытие отделить от обнаруженных уязвимостей.
3. Нормализовать package identity/CVE aliases; применить доверенные VEX feeds в
   порядке own → Docker → Aqua и отдельно действующие risk acceptances.
4. Сохранить raw findings, effective findings и каждое применённое решение с provenance.
5. Вычислить release policy: например, active Block → fail, Warn → success с отчётом.
   Просроченное/неподходящее исключение не подавляет finding. Ошибка проверки → fail.
6. Публиковать/promote release только после success. Не использовать findings count
   в dashboard в качестве неявного release gate.

Промежуточный exit code scanner-а по findings не должен преждевременно останавливать
этот процесс. Например, Trivy может собирать JSON с findings exit code 0, сохраняя
отдельную обработку ошибок исполнения; Socket scan create работает без native report.
Нельзя blanket `continue-on-error` превратить падение scanner-а в разрешение релиза.

Варианты центрального хранения:

| Вариант | Сильная сторона | Ограничение |
|---|---|---|
| Git registry + OpenVEX + adapters | Review, история, воспроизводимость; подходит для POC | Schema/evaluator/adapters надо поддерживать самим |
| Dependency-Track | SBOM inventory и triage уязвимостей, CycloneDX VEX | Не универсальное управление всеми типами findings; CI/native sync всё равно нужен |
| DefectDojo | Агрегация findings и risk acceptance с expiry/API | Приём отчёта не означает автоматический контроль exit code исходного scanner-а |
| Исключения отдельно в каждом scanner | Нативный dashboard/вывод | Несколько источников истины, рассинхронизация и сложный отзыв |

Источники: [Dependency-Track suppression](https://docs.dependencytrack.org/triage/suppression/),
[DefectDojo risk acceptance](https://docs.defectdojo.com/triage_findings/findings_workflows/os__risk_acceptance/).

Если требуется единый результат также ВНУТРИ каждого dashboard, registry должен
синхронизироваться с native механизмами инструментов. Для Socket это отдельный
sync service с узкими resolutions и возможностью отзыва; для несовместимых VEX
потребителей нужны exports/adapters. Без sync центральный gate корректен, но native
UI scanner-а может продолжать показывать исходную находку. Это ожидаемо и должно
быть явно обозначено разработчикам.

## SBOM и сборка релиза

Для npm manifest/lockfile SCA и инвентаря разрешённых зависимостей не требуется
`yarn build`. Но это не точный перечень ПО в конечном Docker image: в нём есть
OS packages, Node runtime, platform-specific/optional зависимости, файлы install scripts
и результат bundling. Точный runtime inventory строится по фактическому image.

Рекомендуется использовать уже существующую Docker build, без повторной сборки:

- Включить BuildKit SBOM (`sbom: true` у build-push-action / `--sbom=true` у buildx)
  и provenance, сохранить SPDX attestation с image digest.
- Сканировать готовый image по immutable digest, по каждой поставляемой architecture,
  например Trivy. Сохранить runtime SBOM и raw vulnerability report.
- Сохранить отдельный source/build dependency SBOM для dev/build dependencies.
  Не смешивать их с runtime без отметки контекста.
- Сверить SBOM coverage: OS packages, npm packages, base image, версии/PURL и target
  platform. SBOM не гарантирует обнаружение каждого встроенного/сгенерированного компонента.
- Если registry push нужен для attestations/scan, сначала публиковать candidate в
  staging/quarantine scope, а production tag/release/deploy делать после gate.
  Должен продвигаться тот же digest, который проверен, без повторной сборки.

В текущем Dockerfile Voting выполняется yarn install, затем в final stage копируется
весь `/app`: туда попадает node_modules, включая установленные dev dependencies.
Поэтому runtime image scan важен; наличие двух stages само по себе не означает
удаление build dependencies. Dockerfile в рамках этого изменения не исправляется.

[Docker SBOM attestations](https://docs.docker.com/build/metadata/attestations/sbom/),
[Docker build attestations](https://docs.docker.com/build/metadata/attestations/).
