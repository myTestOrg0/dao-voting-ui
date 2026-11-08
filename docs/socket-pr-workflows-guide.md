# Socket POC: рабочая интеграция

## Что находится в PR

12 изменённых файлов относительно develop. Исходный `.github/workflows/socket.yaml` не меняется.

| Файл | Назначение |
|---|---|
| `.github/workflows/socket-native-pr.yaml` | Полный снимок PR, серверные действия и нативные Alert Resolutions Socket |
| `.github/workflows/socket-vex-pr.yaml` | Полный снимок PR, затем собственный VEX-вердикт |
| `.github/workflows/socket-pr-test.yaml` | Baseline настоящей develop; прежнее имя сохранено для ручного запуска до merge |
| `.github/scripts/install-socket-cli.sh` | Проверка хешей и установка отдельного CLI без lifecycle scripts |
| `.github/tools/socket-cli/dependencies.lock` | Зафиксированные Socket 1.13.1 и транзитивные зависимости с SHA-512 |
| `.github/scripts/socket-create-scan.sh` | Создание scan, явный выбор PR/baseline, сохранение кода создания |
| `.github/scripts/socket-summary.py` | Чтение серверных alert.action, список CVE в логе и Actions Summary, итоговый код |
| `.github/scripts/socket-vex-fetch.py` | Получение центральных источников по разрешённым Git-репозиториям, фиксация SHA |
| `.github/scripts/socket-vex-evaluate.py` | Сопоставление CVE/GHSA, точного npm PURL и статуса OpenVEX |
| `.github/scripts/socket-vex-pipeline.py` | Применение VEX к результатам скана и финальный вердикт |
| `.github/socket-vex-sources.json` | Идентификатор продукта, источники и их порядок |
| Этот документ | Эксплуатация, границы решения и план проверок |

Лаборатория, тесты, инструменты измерения, HTML-отчёт и исторические JSON сохранены в ветке
[`codex/socket-poc-lab-archive`](https://github.com/myTestOrg0/dao-voting-ui/tree/codex/socket-poc-lab-archive),
снимок `863415518ea0526288375c7aeb5085de8c91b782`.
Локальная копия: соседняя папка `socket-poc-lab`. В рабочие сканы и PR эти материалы не входят.
Fixtures приоритетов остаются в отдельном центральном репозитории
[`vexel`](https://github.com/myTestOrg0/vexel/pull/1), в `poc/socket/fixtures`; рабочий загрузчик читает только `pkg`.

## Full Scan, PR scan и reachability — разные понятия

**Full Scan** — сохранённый результат анализа полного набора обнаруженных зависимостей конкретного снимка.
Он включает прямые и транзитивные зависимости, восстановленные из поддерживаемых манифестов/lockfiles.
Это не означает сборку приложения, анализ всего исходного кода или проверку содержимого Docker image.

**PR scan** в GitHub App Socket — проверка изменений зависимостей в PR: новых пакетов/версий и связанных алертов.
Отдельный project report может содержать полный снимок. Наличие baseline само по себе не переключает CLI на diff.

**Наши PR workflows** создают Full Scan для head SHA PR и показывают все нерешённые находки снимка,
включая существовавшие до PR. Сравнения base/head сейчас нет. Это выбранный пользователем режим.
**Baseline** создаёт такой же manifest Full Scan, но для настоящей develop, и обновляет dashboard head.
**`--reach`** добавляет локальный анализ исходников и зависимостей; это отдельная ось, а не синоним Full Scan.

## Baseline develop

Запуск: Actions → Socket develop baseline → Run workflow. До merge выбирать ветку `socket-pr-analysis`:
workflow и скрипты берутся из неё, но сканируемые файлы — из отдельного checkout `develop`.
После merge workflow запускается автоматически при push в develop; пока PR не merged, этот push-триггер ещё не активен.

1. Checkout инструментов в `tooling`, настоящей develop в `candidate`, без сохранения GitHub credentials.
2. Получение реального SHA через `git rev-parse HEAD` в `candidate`.
3. Установка отдельного Socket CLI из проверенного lockfile в RUNNER_TEMP. Это не npm install приложения.
4. Из `candidate` выполняется:

```sh
socket scan create --org lido-labs --repo dao-voting-ui \
  --branch develop --commit-hash "$SCAN_SHA" \
  --default-branch --set-as-alerts-page --json .
```

5. Серверные результаты читаются API и выводятся в лог/Summary, даже если обнаружены проблемы.
6. API репозитория проверяет, что default_branch = develop и head_full_scan_id соответствует созданному scan.
   `baseline-head.json` сохраняет доказательство. Для проверки нужен scope `repo:list`;
   публикация scan и проверка head — отдельные операции, поэтому ошибка чтения metadata не доказывает провал публикации.
7. Summary и JSON загружаются в artifact независимо от красного вердикта.

Именно head default branch питает страницы Alerts/Dependencies. Их асинхронное обновление может отставать от создания scan.
PR-флаг `--no-set-as-alerts-page` не даёт тестовым снимкам заменить этот baseline.

## Флаги наших команд

| Аргумент | Зачем нужен |
|---|---|
| `scan create` | Подкоманда создания сохранённого снимка, не отдельный verdict/report |
| `--org lido-labs` | Организация Socket; это не имя GitHub-организации |
| `--repo dao-voting-ui` | Репозиторий в Socket, к которому привязывается scan |
| `--branch NAME` | Метаданные ветки; флаг сам не делает git checkout |
| `--commit-hash SHA` | Метаданные коммита; фактическое содержимое обеспечивает checkout |
| `--json` | Машиночитаемый результат создания; сам не включает вывод всех CVE или проверку политики |
| `.` | Позиционный TARGET: рекурсивное автообнаружение поддерживаемых манифестов/lockfiles в текущем каталоге с учётом игнорирования |
| `--no-set-as-alerts-page` | PR: сохранить scan, не обновлять основной dashboard |
| `--default-branch` | Baseline: назначить ветку scan default branch в Socket; не меняет default branch GitHub |
| `--set-as-alerts-page` | Baseline: назначить scan для основного отчёта default branch |

Обычный PR запускает ту же команду, но с head веткой/SHA и `--no-set-as-alerts-page` вместо двух baseline-флагов.
Файлы `package.json` и `yarn.lock` не перечисляются вручную. Сборка/установка приложения не запускаются.

### Нативный отчёт CLI: поддерживается, но в рабочей обвязке не используется

```sh
socket scan create --org lido-labs --repo dao-voting-ui \
  --branch "$SCAN_BRANCH" --commit-hash "$SCAN_SHA" \
  --no-set-as-alerts-page --report --report-level warn .
```

- `--report`: дождаться результата и выполнить штатную проверку политики. Block (`error`) → ненулевой код; Warn → 0.
- `--report-level warn`: включить Warning в вывод; это порог отображения, а не изменение exit code.
- `--markdown`: альтернативный формат вывода; сам не публикует GitHub-комментарий.
- `--pull-request NUMBER`: привязка метаданных PR; сам не создаёт diff и не выдаёт право комментировать.
- `--auto-manifest`: запускает генерацию манифестов инструментами сборки для нужных экосистем; для нашего Yarn snapshot не требуется.

Socket умеет показывать алерты без нашей обвязки. Bare `scan create` проверяет создание scan,
а не отсутствие проблем. Native `--report` проверяет Block, но не делает Warn красным.
В проверенной версии 1.13.1 генератор native report также повторно применяет правила по типу алерта;
это может отличаться от серверного `.action` с учётом reachability/Resolution.
Наш evaluator читает серверные `.action`, а затем вводит дополнительное требование:
нерешённая vulnerability с действием Warn или Monitor тоже даёт красный optional check.
Ignore не делает native-вариант красным. Non-vulnerability Block/Warn также учитываются.

GitHub-права всех трёх workflow: только `contents: read`. Summary пишет runner через GITHUB_STEP_SUMMARY,
artifact загружается Actions-механизмом; комментарии в PR не создаются.
Красный check не запрещает merge, пока он не включён в required checks/rulesets.
Слово optional в имени job само по себе ничего не настраивает.

## Reachability: отдельный лабораторный режим

Измерительный workflow и observer перенесены в архив. В трёх рабочих workflow нижеописанный режим сейчас не включён.
Использовавшаяся команда дополняла create следующими флагами:

| Флаг | Назначение |
|---|---|
| `--reach` | Локальный full application static reachability анализ кода приложения и зависимостей |
| `--reach-version 15.14.1` | Выбор версии Coana engine отдельно от версии Socket CLI; версия сама по себе не является hash pin движка |
| `--reach-disable-analytics` | Отключение дополнительной аналитики и связанных оптимизаций кеширования; не отключает отправку scan/facts |
| `--reach-retain-facts-file` | Только измерение: оставить локальный facts-файл; observer затем удалял его, чтобы следующий обычный scan не использовал устаревшие facts |

Управление отказами, сейчас не включено:

| Флаг | Последствие |
|---|---|
| `--reach-analysis-timeout` | Предел анализа, по умолчанию 10m |
| `--reach-analysis-memory-limit` | Предел памяти, по умолчанию 8GB |
| `--reach-continue-on-analysis-errors` | Продолжить при ошибках анализа, с fallback на precomputed |
| `--reach-continue-on-install-errors` | Продолжить при ошибках получения/установки зависимостей |
| `--reach-continue-on-missing-lock-files` | Продолжить для соответствующих проектов без обязательного lockfile |
| `--reach-continue-on-no-source-files` | Продолжить, когда исходники не найдены |
| `--reach-fallback-to-regular-scan` | При провале reachability сделать обычный SCA scan; успешный fallback не доказывает успешный reachability |

Ошибка анализатора, timeout/OOM или установки может остановить команду с ненулевым кодом,
в том числе 1. В CLI 1.13.1 `output-create-new-scan` использует `result.code ?? 1` при `ok=false`.
При этом `unknown`, `undeterminable` и `missing_support` в отдельных результатах не равнозначны провалу процесса:
scan может завершиться успешно с частичным reachability coverage.
Exit 1 от нашего evaluator при оставшихся CVE также не означает сбой анализатора.
Нужно различать creation exit, завершённость анализа, coverage и финальный verdict.

В эксперименте с Voting явного `yarn build`/Next build/Docker build не было.
Engine анализировал локальный код, получал зависимости и формировал facts; CLI отправлял манифесты и сжатые facts,
а не архив checkout. Измерено около 626413 байт трёх файлов-кандидатов загрузки; это не полный сетевой аудит.
Facts являются производными данными анализа; отсутствие передачи исходников целиком не означает отсутствие метаданных кода.

## VEX и план проверки приоритетов

Рабочий порядок: **own → Docker DHI → Aqua VEX Hub**, первое применимое statement для конкретной package/version/CVE.
Сначала проверяется идентичность продукта и применимость источника, затем приоритет.
`not_affected`/`fixed` снимают конкретную находку; `affected`/`under_investigation` сохраняют её и останавливают нижние источники.
Разные CVE и версии оцениваются независимо. Ошибочный/противоречивый документ не должен давать зелёный результат.

Native и VEX — независимые варианты сравнения: native соблюдает серверные Resolutions;
VEX восстанавливает проигнорированные сервером vulnerability findings до Monitor и применяет центральные исключения.
Поэтому серверный Ignore в VEX-варианте сам по себе недостаточен для исключения.
У этого подхода есть граница: нельзя восстановить находку, которую сервер вообще не вернул.
VEX влияет на наш финальный Actions exit code/Summary, но не меняет алерты в Socket dashboard.

**Текущее ограничение:** скан npm-манифестов не доказывает использование конкретного DHI image.
DHI загружается для provenance, но не может снимать находки такого скана. Aqua в проверенном снимке не содержал npm-данных.
Fixtures с названиями Docker/Aqua проверяют роли приоритета, а не подлинные решения этих поставщиков.

### Этап 1: детерминированный тест evaluator

Использовать отдельный synthetic product из `vexel/poc/socket`; фиксировать SHA всех источников.
Восемь центральных cases уже выполнялись успешно в архивном PR workflow.

| Сценарий | Победитель / ожидаемое состояние целевой находки |
|---|---|
| Own affected, Docker not_affected | Own, находка остаётся |
| Own not_affected, Docker affected | Own, находка исключается |
| Own про другую CVE, Docker not_affected | Docker |
| Own и Docker про другие CVE, Aqua not_affected | Aqua |
| Own under_investigation, Docker not_affected | Own, находка остаётся |
| Другая версия | Исключение не применяется |
| Истёкший own без других statements | Исключение не применяется |
| Нет VEX | Исходная находка остаётся |

Дополнить: другой product/image digest/архитектура, CVE↔GHSA alias, конфликт статусов одного источника,
невалидный JSON/статус, недоступный источник, отзыв statement, обновление версии документа.
Проверять не только exit code, но выбранный source, status, document ID, SHA и original/effective action.
При неполной проверке итог красный с отдельным `verification_incomplete`, а не «уязвимостей нет».

### Этап 2: сквозной тест Socket → VEX → Actions

1. Взять реальный scan и конкретную finding, не менять baseline между контрольными вычислениями.
2. Выполнить no-VEX / own under_investigation / own not_affected / отзыв own на изолированном тестовом продукте.
3. Подтвердить, что меняется только выбранная package/version/CVE; соседние CVE/версии остаются.
4. Для перехода job 1→0 использовать изолированный набор с одной находкой.
   При полном Voting snapshot одно исключение не сделает job зелёным: остаются другие CVE.
5. Положительные Docker/Aqua live cases проверять отдельно на подходящем image digest и экосистеме.
   До добавления image-context matching такие тесты не считаются реализованными.
6. Сохранить scan ID, commit, SHA источников, решение и screenshot Summary в лаборатории/архиве.

Источники:
[Socket scan](https://docs.socket.dev/docs/socket-scan),
[PR scanning](https://docs.socket.dev/docs/socket-for-github-pull-request-scanning),
[Full application reachability](https://docs.socket.dev/docs/full-application-reachability),
[Reachability results](https://docs.socket.dev/docs/reachability-results).
