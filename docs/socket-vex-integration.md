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

Warn не блокирует, Block блокирует согласно native CLI report. Ошибки API или
невозможность получить отчёт завершают проверку ошибкой, а не успешным «0 findings».
Summary строится по текущему scan ID и показывает package/version, CVE/GHSA, severity,
действие и первую исправленную версию, если она известна. Счётчики дедуплицируются по
экосистеме, package/version и advisory. Это не число уникальных CVE организации.
Monitor/Ignore сохраняются в JSON. Для forks GitHub обычно не выдаёт repository secret:
такой запуск не сможет сканировать и не должен считаться чистым.

Ограничение CLI: в исходнике `socket@1.13.1` `generate-report.mts` native verdict
вычисляется по `securityPolicyRules[alertType].action`. Summary отдельно показывает
серверный `alert.action`. До включения сложных policy rules/resolutions/VEX нужно
проверить их согласованность; совпадение с verdict dashboard не предполагается.

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

Сделать отдельный CI adapter после получения исходного Socket scan. На первом этапе
он только добавляет колонки VEX status/source/reason в Summary, не меняя gating.
Следующим этапом, после проверки fixtures, он может рассчитывать effective verdict.
Если VEX разрешает исключения, native CLI exit code нельзя просто оставить финальным
вердиктом: сбор scan, ошибки инфраструктуры и решение effective policy надо разделить.
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
не требуется. В PR scanner эти write scopes добавлять не нужно. Нативное влияние
resolutions на CLI 1.13.1 нужно подтвердить тестом перед таким вариантом.

## Проверки для следующего этапа POC

1. Один и тот же package/version/CVE: own `affected` против Docker `not_affected` → finding остаётся.
2. Own `not_affected` с обоснованием против upstream `affected` → исключение с указанием own.
3. Own без данного CVE → fallback Docker, затем Aqua; отдельно сравнить поведение Trivy.
4. Другая версия, arch/distro, image digest или npm вместо Debian → исключение не применяется.
5. Нет VEX, конфликт/сломанный feed, under_investigation → finding остаётся видимым.
6. Отзыв исключения → finding возвращается; raw scan всегда доступен.
7. В release повторить scan текущего артефакта и VEX evaluation; проверить warning/block
   на одной и той же fixture, затем убедиться, что публикация зависит от effective verdict.
