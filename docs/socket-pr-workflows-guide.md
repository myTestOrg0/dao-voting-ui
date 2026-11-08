# Socket PR workflows and exception management

Обновлено 8 ноября 2026. Это руководство описывает текущий POC в `myTestOrg0/dao-voting-ui`.

## Красный статус без блокировки merge

Security check завершается **failure**, если после исключений остался хотя бы один CVE,
включая Monitor, или actionable alert с Warn/Block. Ignore в native-варианте и
применимый not_affected/fixed в VEX-варианте исключают находку из этого критерия.
Неизвестное действие или ошибка проверки тоже дают failure, но помечаются как
verification incomplete, а не как обнаруженная уязвимость.

Не используется continue-on-error: оно скрывало бы нужный красный статус. Merge
разрешается настройками GitHub: эти checks не должны быть required в branch protection
или rulesets. Проверка develop показала отсутствие protection и применимых rulesets;
при красном native check GitHub API вернул MERGEABLE / UNSTABLE. Это не автоматический
merge. Если позже сделать эти checks required, их failure начнёт блокировать merge.

## Явные workflow

| Файл | Назначение | Check |
|---|---|---|
| `.github/workflows/socket-native-pr.yaml` | Snapshot scan и native resolutions | Socket native findings (optional) |
| `.github/workflows/socket-vex-pr.yaml` | Snapshot scan и центральный VEX | Socket VEX findings (optional) |
| `.github/workflows/socket-pr-test.yaml` | Ручные reachability и native lifecycle эксперименты | Socket POC experiments |

Оба PR workflow имеют permissions contents: read, checkout точного head commit и
persist-credentials: false. Они не пишут комментарии в PR. CLI и его npm dependencies
закреплены по хешам. Исходный socket.yaml не меняется.

## Native pipeline

1. Checkout кандидата PR и установка hash-pinned Socket CLI во временный каталог.
2. `socket scan create ... --json .` автоматически обнаруживает manifests/lockfiles.
   App dependencies не устанавливаются; production build не запускается.
3. API возвращает полный scan. В каждой находке action/actionSource уже отражают
   серверные policy, reachability и native resolutions.
4. Evaluator формирует лог, Summary и report artifact. Не исключённые CVE делают
   check красным. GitHub не блокирует merge, пока check optional.

### Как добавить нативную неприменимость в Socket console

1. Открыть организацию lido-labs и Organization Alerts. Отфильтровать repository
   dao-voting-ui, пакет, точную версию и CVE/GHSA. Для конкретного PR можно сначала
   открыть ссылку на scan из Actions Summary; PR scan не заменяет alerts page default branch.
2. Выбрать finding и Resolve. Если реальная оценка показывает неприменимость,
   использовать False positive и записать обоснование в comment. Tolerable risk —
   принятие применимого риска, это другая причина; Remediated — устранено/смягчено.
   Не объявлять неприменимость лишь ради зелёного check.
3. Проверить scope. Предпочтительно repository + npm namespace/name + exact version +
   alert type + конкретный CVE/GHSA. Отсутствующая dimension расширяет исключение.
   Если UI не позволяет выразить точный selector, использовать Resolution API.
4. Запустить новый PR scan. Подходящая находка получает Ignore с actionSource=resolution.
   При наличии других не исключённых CVE check остаётся красным.
5. Для отзыва открыть Resolved и удалить resolution. Следующий scan снова получает
   действие политики. Уже сохранённый Actions artifact не переписывается.

В использованном resolution API нет универсального expires_at: срок пересмотра
нужно вести отдельно и отзывать запись автоматизацией, если expiry нужен организации.
Это одна из причин иметь центральный реестр решений.

Точный selector, проверенный реальным тестом:

```json
{
  "location.repo": "dao-voting-ui",
  "artifact.type": "npm",
  "artifact.namespace": "",
  "artifact.name": "lodash",
  "artifact.version": "4.17.11",
  "finding.alertType": "criticalCVE",
  "finding.cveId": "CVE-2019-10744"
}
```

Тест подтвердил Warn → Ignore → Warn после удаления; две контрольные CVE не изменились.
Временный resolution удалён, политика не менялась. Это не assessment неприменимости
lodash и не тест реального Block → Ignore.

Документация: https://docs.socket.dev/docs/alert-resolutions и https://docs.socket.dev/docs/vigil.

## VEX pipeline

Центральный репозиторий клонирован рядом с Voting:
`/Users/lido/Documents/1-Projects/socket-dev-poc/vexel`.
Изменения изолированы в `codex/socket-poc-integrations`, draft PR:
https://github.com/myTestOrg0/vexel/pull/1.

Конфигурация источников — `.github/socket-vex-sources.json`:

1. own — myTestOrg0/vexel, сейчас POC branch;
2. Docker DHI — docker-hardened-images/advisories;
3. Aqua — aquasecurity/vexhub.

Каждый ref разрешается в commit SHA один раз на запуск. Дальше файлы читаются из
этого snapshot; сохраняются revision и SHA-256 документов. Используется публичный
Git read, без отдельного PAT и без cross-organization GitHub API permissions.
После review/merge центрального PR own ref следует перевести с POC branch на main.

Порядок работы:

1. Создать Socket scan и получить исходные findings, не завершая job преждевременным
   native CLI policy verdict.
2. В этом сравнительном варианте native Ignore для vulnerability не считается
   исключением: finding возвращается в Monitor перед VEX evaluation. Это относится
   и к native resolutions, и к policy Ignore для CVE. Метаданные исходного scan остаются
   в raw-server-report.json. Единственный источник исключений CVE здесь — центральный VEX.
3. Из каждого source загрузить применимые package documents. Неподдерживаемая экосистема
   фиксируется в provenance; это отсутствие VEX coverage, а не разрешение finding.
4. На каждую пару package/version/advisory искать первое применимое утверждение:
   own → Docker → Aqua. Другое CVE или другая версия не останавливают fallback.
   Высокоприоритетное affected/under_investigation предотвращает низкоприоритетное
   not_affected. Конфликтующие matching статусы одного source дают verification error.
5. Только применимые not_affected/fixed исключают finding. Проверяются product scope,
   exact npm PURL/version и CVE/GHSA aliases. Не поддержанные qualifiers/subpaths
   без соответствующего контекста не матчятся. Ошибка источника не даёт clean result.
6. Сформировать effective findings и **один окончательный exit code**. Если остались
   CVE — failure; check optional в GitHub, поэтому merge разрешён.

В own feed добавлены два under_investigation для Voting/lodash. Они сохраняют реальные
находки открытыми. Синтетические not_affected/affected fixtures расположены отдельно в
poc/socket/fixtures и используют другой product ID; production evaluation их не читает.
Восемь central priority cases выполняются отдельным job с сохранением evidence.
Названия Docker/Aqua в fixtures — слоты приоритета, не авторство vendor statements.

В manifest-only pipeline документы Docker DHI загружаются и фиксируются в provenance,
но не получают права подавлять findings: у этого scan нет проверенного DHI image identity.
В фактическом snapshot загружено 29 npm package documents; некоторые содержат разные
статусы одного package/version/CVE в контексте разных образов. Нельзя выбирать удобный
not_affected из такого набора или терять image scope. Для image pipeline понадобится
привязка vendor statements к проверяемому digest. Aqua snapshot не содержит npm-раздела.

Docker DHI statements нельзя переносить на обычный node:20-alpine лишь по совпадению
CVE или имени npm-пакета. VEX описывает применимость к продукту, а не глобальную амнистию CVE.
VEX-вариант меняет CI verdict/отчёт; он не удаляет исходные findings из Socket dashboard.

## Full application reachability

Запуск:

```sh
gh workflow run socket-pr-test.yaml --ref socket-pr-analysis -f run_reachability=true
```

Команда анализа:

```sh
socket scan create --reach --reach-version 15.14.1 \
  --reach-disable-analytics --reach-retain-facts-file \
  --org lido-labs --repo dao-voting-ui --json .
```

Это **анализ приложения на runner**, а не production build pipeline. В workflow нет
шагов yarn build, next build или docker build. Engine получает код приложения и код
зависимостей локально, может скачивать analyzers/packages и использовать toolchain.
Для compiled ecosystems могут потребоваться build scripts или операции компиляции;
один флаг --reach не означает одинаковую сборку всех языков.

В Voting анализ строит модель вызовов JS/TS и определяет доступность функций,
затронутых CVE. App source присутствует в checkout runner. Manifests и созданный
.socket.facts.json передаются Socket; facts содержат dependency/reachability metadata,
имена файлов и позиции вызовов. По проверенному upload-коду CLI facts сжимаются Brotli,
а весь checkout/node_modules не добавляется как архив.

Для измерения включён ограниченный observer Node subprocesses и file streams CLI.
Он не сохраняет source text, полные аргументы команд или значения env. В public
artifact помещается только reachability-inventory.json, не raw facts. Retained facts
после измерения удаляется, чтобы manifest-only scan случайно не переиспользовал его.

Размеры файлов и результаты наблюдения должны читаться из конкретного run evidence,
а не из фиксированного обещания «N байт кода». Сжатые facts — производные от кода данные;
их размер не равен размеру исходников. Multipart headers и весь сетевой трафик engine
этим измерением не учитываются. Observer не является полным network/kernel audit.

Optional reachability analytics отключена в измерительном запуске. В реальном сравнении
на том же snapshot 1433 компонента и 217 vulnerability findings дали 53 Warn без full
analysis и 35 с ним: 24 Warn→Monitor, 6 Monitor→Warn. В новом режиме «все не исключённые
CVE делают check красным» понижение до Monitor само по себе не делает check зелёным.

Источники: https://docs.socket.dev/docs/precomputed-reachability,
https://docs.socket.dev/docs/full-application-reachability и исходники закреплённого CLI 1.13.1.


### Измеренный payload reachability

Run 42488906212, engine 15.14.1, analytics disabled:

| Файл | Размер |
|---|---:|
| package.json | 3 196 bytes |
| yarn.lock | 526 871 bytes |
| .socket.facts.json.br | 96 346 bytes |
| Всего содержимого этих трёх upload streams | 626 413 bytes |

Несжатые facts — 6 534 393 bytes. Top-level keys: components и workspaceDiagnostics;
3 727 filename fields — это число вхождений полей, не уникальных файлов. Поля имён,
позиций и графа отправляются. Индикаторных string-полей code/sourceCode/content/snippet
в этом facts-файле не обнаружено; это не полный аудит всех возможных сериализаций.
Observer зафиксировал npm pack и sparjs; явных yarn build/next build/docker build шагов нет.
626 413 bytes не включают multipart headers и остальной API/download трафик.
