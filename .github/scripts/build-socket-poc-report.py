"""Build a portable illustrated report from committed POC evidence, no dependencies."""
import html
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs/socket-poc'
EVIDENCE = DOCS / 'evidence'
manifest = json.loads((EVIDENCE / 'manifest-scan.json').read_text())
reach = json.loads((EVIDENCE / 'reachability.json').read_text())
replay = json.loads((EVIDENCE / 'vex-replay.json').read_text())
e = lambda x: html.escape(str(x))
link = lambda url, label: f'<a href="{e(url)}">{e(label)}</a>'


def table(headers, rows, classes=''):
    return f'<div class="table-wrap"><table class="{classes}"><thead><tr>'+''.join(f'<th>{e(x)}</th>' for x in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{x}</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def flow(labels, title):
    width=1150; n=len(labels); gap=27; box=(width-30-gap*(n-1))/n
    svg=[f'<svg viewBox="0 0 {width} 145" role="img" aria-label="{e(title)}" xmlns="http://www.w3.org/2000/svg"><title>{e(title)}</title>']
    for i,label in enumerate(labels):
        x=15+i*(box+gap)
        svg.append(f'<rect x="{x}" y="20" width="{box}" height="100" rx="10" fill="{["#edf4fa","#e9f4ef","#fff3df"][i%3]}" stroke="#afbdca"/>')
        parts=label.split('|')
        for j,text in enumerate(parts):
            svg.append(f'<text x="{x+box/2}" y="{58+j*25}" text-anchor="middle" font-family="Arial,sans-serif" font-size="{17 if j==0 else 15}" fill="#162b3d">{e(text)}</text>')
        if i<n-1:
            ax=x+box+4
            svg.append(f'<path d="M {ax} 70 h 16 m -5 -5 l 5 5 -5 5" fill="none" stroke="#506575" stroke-width="2"/>')
    return ''.join(svg)+'</svg>'


native=manifest['native_probe']['checks']
change_counts={}
for row in reach['action_changes']:
    key=row['before']+' → '+row['after'];change_counts[key]=change_counts.get(key,0)+1

cases=[
 {'id':'PR01','kind':'live','name':'Manifest scan with generic discovery','status':'passed','evidence':manifest['run_url'],'actual':'1433 components, 217 vulnerability findings, 53 Warn, exit 0'},
 {'id':'PR02','kind':'live','name':'Full application reachability','status':'passed','evidence':reach['run_url'],'actual':'1433 components, 217 vulnerability findings, 35 Warn, exit 0; creation/analysis step 66 sec'},
 {'id':'OUT01','kind':'live','name':'CVE details inside job step log','status':'passed','evidence':manifest['run_url'],'actual':'FINDING lines contain package, version, CVE/GHSA, severity, server action and fix'},
 {'id':'PIN01','kind':'live','name':'Hash pinned CLI install','status':'passed','evidence':manifest['run_url'],'actual':'CLI tarball SHA-512 and dependency lock SHA-256, 33 packages have SHA-512 SRI'},
 {'id':'PIN02','kind':'fixture','name':'Reject altered dependency lock','status':'passed','evidence':'.github/scripts/tests/test_socket_vex.py','actual':'One byte change causes verification failure before installation'},
 {'id':'N01','kind':'live','name':'Native resolution list','status':'blocked','evidence':manifest['run_url'],'actual':'HTTP 403'},
 {'id':'N02','kind':'live','name':'Native create dry run','status':'blocked','evidence':manifest['run_url'],'actual':'HTTP 403, no resolution persisted'},
 {'id':'N03','kind':'pending','name':'Native create apply rescan revoke','status':'not_run','evidence':'Requires separate resolution token and server snapshot validation','actual':'No end-to-end suppression claim'},
 {'id':'UNIT01','kind':'fixture','name':'Unit and integration evaluator suite','status':'passed','evidence':reach['run_url'],'actual':'17 test methods passed in Actions'},
]
for x in replay['cases']:
    cases.append({'id':x['id'],'kind':'offline_replay','name':x['name'],'status':x['status'],'evidence':'evidence/vex-replay.json','actual':f"expected exit {x['expected_exit']}, actual {x['actual_exit']}"})
cases += [
 {'id':'V11','kind':'pending','name':'Production organizational OpenVEX decision','status':'not_run','evidence':'Requires an approved applicability assessment','actual':'Synthetic VEX was not enabled in normal PR gate'},
 {'id':'REL01','kind':'pending','name':'Release image SBOM and promotion gate','status':'not_run','evidence':'Release workflow was not modified','actual':'Planned separate phase'},
 {'id':'FEED01','kind':'partial','name':'Three-source priority','status':'partial','evidence':'V03 V04 V08 V10','actual':'Priority tested with synthetic sources; real own Debian document gives no npm match. Live Docker/Aqua matching not proven.'},
]
(DOCS/'test-results.json').write_text(json.dumps({'as_of':'2026-11-08','tested_commit':manifest['commit'],'cases':cases},ensure_ascii=False,indent=2))

status={'passed':'<span class="badge good">Пройдено</span>','blocked':'<span class="badge warn">HTTP 403</span>', 'not_run':'<span class="badge muted">Не выполнено</span>','partial':'<span class="badge warn">Частично</span>'}

sections=[]
sections.append(('Итог и границы проверки', f'''
<p class="lead">Для всех PR предлагаем manifest scan с серверными действиями Socket. Full application reachability доступен отдельным запуском и в POC дал более точную классификацию. Для общих исключений предлагаем центральный реестр и единый evaluator; OpenVEX используется для применимости CVE.</p>
<div class="metrics"><div><b>1 433</b><span>компонента в обоих сканах</span></div><div><b>217</b><span>находок уязвимостей в обоих сканах</span></div><div><b>53 → 35</b><span>Warn после full application анализа</span></div><div><b>17 + 10</b><span>тестовых методов и CLI replay сценариев</span></div></div>
<p>Репозиторий <code>myTestOrg0/dao-voting-ui</code>, Socket organization <code>lido-labs</code>. Проверяем весь snapshot кандидата PR, не только diff. GitHub token имеет <code>contents: read</code>; третьестороннее приложение с write доступом не устанавливается. </p>
<div class="note">Успех Actions не доказывает отсутствие уязвимостей. В обоих реальных сканах Block отсутствует, Warn не блокирует. Работа нативных исключений не подтверждена: API вернул HTTP 403. VEX-решения в тестах синтетические и не являются утверждением о реальной неприменимости lodash.</div>
<h3>Два независимых выбора</h3>
{flow(['Как получить данные|Manifests или --reach','Как учесть исключения|Native или central VEX','Как принять решение|Effective actions → exit code'],'Оси интеграции Socket')}
<p>Способ сканирования и механизм исключений выбираются отдельно. Возможны четыре комбинации: manifests × native, manifests × VEX, reach × native, reach × VEX. Они не требуют четырёх разных источников организационной политики.</p>
<p class="source">Реальные запуски: {link(manifest['run_url'],'manifest PR run')} · {link(reach['run_url'],'reachability comparison run')}. Scan IDs: <code>{e(manifest['scanId'])}</code> и <code>{e(reach['scanId'])}</code>.</p>
'''))

sections.append(('Варианты запуска в pull request', f'''
<h3>Вариант A Manifest scan</h3>
{flow(['Checkout PR|Файлы кандидата','Socket discovery|Manifests и lockfiles','Socket API|Граф и precomputed reach','Server actions|Summary и итоговый код'],'Manifest PR scan')}
<p>CLI рекурсивно выбирает поддерживаемые build descriptors и lockfiles. В фактическом скане это <code>package.json</code> и <code>yarn.lock</code>. Список этих файлов в команде не задан. Зависимости приложения не устанавливаются, <code>yarn build</code> и Docker build не запускаются. Устанавливается только закреплённый CLI в отдельный временный каталог.</p>
<p>Precomputed reachability использует анализ вызовов внутри зависимостей. Исходники приложения ему не нужны. Ограничения включают прямые, приватные и не объявленные в manifest зависимости. Unknown или неподдерживаемый анализ не равен доказанной неприменимости.</p>
<h3>Вариант B Full application reachability</h3>
{flow(['Checkout PR|Исходники и descriptors','Локальный engine|Код приложения и deps','Socket facts|Результаты и call locations','Socket API|Действия для того же scan'],'Full application reachability PR scan')}
<p><code>socket scan create --reach</code> запускает анализ на GitHub runner. Engine может загружать анализаторы и зависимости; требования к package manager и toolchain зависят от языка. Это не команда универсальной production сборки. В нашем workflow нет явных <code>yarn build</code> или <code>docker build</code>. Мы не утверждаем по одному факту успешного скана, что внутри engine не было подготовительных команд.</p>
<p>У compiled ecosystems могут потребоваться build scripts, разрешение зависимостей или операции компиляции. Для JS/TS цель этого режима — построение модели вызовов приложения и зависимостей, а не выпуск Next.js bundle.</p>
<p>Документация допускает сохранение исходников на своём runner. В Socket передаются результаты анализа, содержащие metadata: в нашем ответе API присутствуют имена файлов приложения и позиции вызовов. Это нужно учитывать при оценке границы данных. Managed scans на стороне Socket — отдельный вариант, в этом POC он не использован.</p>
{table(['Критерий','Manifests','Full application'],[['Production build','Не запускается','Не требуется как универсальный шаг; зависит от экосистемы'],['Исходники приложения для анализа','Не нужны','Нужны на runner'],['Подготовка зависимостей приложения','Не нужна для этого npm lockfile scan','Может выполняться engine или заранее в CI'],['Режим в нашем workflow','Автоматически в PR','workflow_dispatch с run_reachability=true'],['Основной компромисс','Быстрота и простота','Дополнительный контекст и ресурсы']])}
'''))

sections.append(('Результаты реального сравнения', f'''
<p>Оба скана относятся к одному commit <code>{e(manifest['commit'])}</code>. Одинаковое число компонентов и vulnerability findings позволяет сравнивать действия на том же наборе зависимостей. Уменьшение Warn не означает, что пакеты или CVE исчезли.</p>
{table(['Метрика','Manifest scan','Full application scan'],[['Компоненты',str(manifest['components']),str(reach['components'])],['Находки уязвимостей',str(manifest['vulnerabilities']),str(reach['vulnerabilities'])],['Block','0','0'],['Warn',str(manifest['actions'].get('warn',0)),str(reach['actions'].get('warn',0))],['Monitor',str(manifest['actions'].get('monitor',0)),str(reach['actions'].get('monitor',0))],['Ignore',str(manifest['actions'].get('ignore',0)),str(reach['actions'].get('ignore',0))],['Итоговый exit code','0','0']])}
<div class="metrics three"><div><b>24</b><span>Warn → Monitor</span></div><div><b>6</b><span>Monitor → Warn</span></div><div><b>66 с</b><span>этап full application scan</span></div></div>
<p>Full application режим не только подавляет предупреждения: он также выявил достижимость для шести находок, которые manifest/precomputed режим оставлял в Monitor. Это аргумент сохранять оба контекста в доказательствах теста.</p>
{table(['Результат reachability для CVE','Число'],[['full scan unreachable','143'],['full scan reachable','43'],['full scan undeterminable','22'],['full scan missing support','3'],['precomputed unknown','6']])}
<p>В ответе API 211 vulnerability records имеют head type <code>full-scan</code>, шесть — <code>precomputed</code>. Следовательно, не все 217 находок получили определённый full application результат. Цифры здесь относятся к component/version/advisory findings, а не к уникальным CVE организации.</p>
<p class="source">Источники: артефакты <code>socket-report</code> и <code>socket-reach-report</code>; сохранённые метрики <code>evidence/manifest-scan.json</code> и <code>evidence/reachability.json</code>. Ссылки на Actions выше сохраняют связь с исходными данными.</p>
'''))

sections.append(('Исключения Native и центральный VEX', f'''
<h3>Нативный механизм Socket</h3>
<p>Socket resolutions задают scope по repository, ecosystem/package/version и finding. Подходящий resolution применяется перед policy. Преимущество — нативный dashboard и серверные действия. Недостаток для организации — отдельный механизм рядом с исключениями Trivy, Docker и остальных scanner-ов.</p>
{table(['Проверка API','Фактический результат','Что это подтверждает'],[[e(x['name']),f"HTTP {x.get('http_status','n/a')}",'API недоступен текущему токену; причина 403 требует проверки scopes, квоты и доступности функции'] for x in native])}
<p>Ни одного resolution не создано или удалено. Для сквозного теста нужны отдельный repo-scoped token и операции list/create/delete, а для чтения конкретной записи — read. Сценарий: исходная находка → узкий resolution → обновление серверного snapshot/rescan → действие и verdict → отзыв → повторное появление. Dry-run даже при HTTP 200 не заменяет этот сценарий.</p>
<h3>Центральный реестр и OpenVEX</h3>
{flow(['Scanner results|Исходные находки','Trusted decisions|Own → Docker → Aqua','Effective findings|VEX и risk acceptance','Policy gate|Один финальный exit'],'Центральные исключения перед итоговым решением')}
<p>Обёртка сначала получает законченный scan, затем применяет решения и лишь после этого выдаёт финальный exit code. Ошибки scanner/API не становятся исключениями. Создание скана выполняется без native CLI <code>--report</code>, поэтому локальный policy report не успевает преждевременно остановить проверку.</p>
<p>VEX подходит для применимости уязвимостей. Принятие риска со сроком действия, исключения лицензий, malware или IaC требуют более общей модели решений. Нельзя кодировать «риск принят» как ложное <code>not_affected</code>.</p>
{table(['Критерий','Socket native','Центральный registry и VEX'],[['Единое решение для нескольких инструментов','Нужна синхронизация с другими системами','Source of truth общий; нужны adapters'],['Отображение в Socket dashboard','Нативное','Без sync исходная находка остаётся'],['Влияние на CI exit code','Через server action','Через effective evaluator до финального exit'],['Сопровождение','Проще для одного продукта','Собственная схема, тесты и контроль версий'],['Текущий статус POC','API 403; применение не проверено','CLI replay проходит; production не включён']])}
<p>Если собственное <code>affected</code> должно отменять также серверное понижение по reachability, нужна явно заданная центральная политика действий. Текущий POC adapter сохраняет server action для affected и только предотвращает более низкоприоритетное VEX-подавление. Он не восстанавливает скрытые native resolutions и не является полноценным policy engine.</p>
'''))

vex_names={'V01':'Без VEX','V02':'Own not affected','V03':'Own affected против Docker not affected','V04':'Own not affected против Docker affected','V05':'Другая версия','V06':'Просроченное решение','V07':'Under investigation','V08':'Fallback к Aqua','V09':'Недоступный файл источника','V10':'Реальный Debian VEX против npm'}
sections.append(('Проверка VEX и границы прототипа', f'''
<p>Для CLI replay взята реальная находка <code>lodash@4.17.11 / CVE-2019-10744</code>. Реальное серверное действие — <b>Warn</b>. Только в контролируемом replay baseline заменён на Block, чтобы проверить изменение <code>1 → 0</code>. Утверждения о неприменимости в этих fixtures синтетические и не являются security assessment.</p>
{table(['ID','Сценарий','Ожидался exit','Получен exit','Результат'],[[e(x['id']),e(vex_names[x['id']]),str(x['expected_exit']),str(x['actual_exit']),status[x['status']]] for x in replay['cases']])}
<p>Приоритет own → Docker → Aqua проверен на синтетических документах. Реальный файл собственного feed <code>myTestOrg0/vexel/pkg/deb/debian/libexpat1/vex.json</code> также проверен: он не подавляет npm finding. Проверенный commit feed — <code>796125e68a6b712a26d036b689ef0600a2700fb8</code>.</p>
<div class="note">Live применение подходящих записей Docker DHI и Aqua к продукту пока не проверено. Voting использует node:20-alpine, собственный feed описывает Debian/DHI Python. Совпадения только CVE недостаточно. Нужны отдельный DHI image test и утверждение, соответствующее конкретному продукту.</div>
<p>POC adapter поддерживает OpenVEX 0.2, точные npm PURL и ограниченный product/subcomponent scope. Qualifiers и subpaths без соответствующих данных не матчятся. Поддержаны CVE/GHSA aliases, приоритет, SHA-256 provenance, конфликтующие статусы и optional organization extension <code>x-poc-expires</code>. Последнее не является стандартным полем OpenVEX.</p>
<p>В обычный PR gate VEX-фильтрация не включена. Для production нужны trusted central configuration, утверждённые решения, проверка подписи/происхождения feed и полный контракт на product identity. Непроверенный PR не должен иметь возможности добавить себе исключение.</p>
<details><summary>Воспроизвести CLI replay</summary><pre>python3 .github/scripts/replay-socket-vex-poc.py \\
  --findings docs/socket-poc/evidence/replay-finding.data \\
  --output /tmp/vex-replay.json</pre><p>Для сценария V10 добавляется <code>--own-feed-sample docs/socket-poc/evidence/own-feed-sample.openvex</code>.</p></details>
'''))

log_lines=(EVIDENCE/'step-log.txt').read_text().splitlines()
svg=['<svg viewBox="0 0 1250 315" role="img" aria-label="Фрагмент настоящего Actions лога" xmlns="http://www.w3.org/2000/svg"><rect width="1250" height="315" rx="12" fill="#142435"/><text x="24" y="38" fill="#b8d8ee" font-family="Arial,sans-serif" font-size="19">Извлечение из реального Actions лога 42470524152</text>']
for i,line in enumerate(log_lines[:5]):
    body=line.split('FINDING |',1)[-1].strip()
    svg.append(f'<text x="24" y="{85+i*39}" fill="#e8f1f7" font-family="monospace" font-size="15">{e(body)}</text>')
svg.append('</svg>')
sections.append(('Лог шага и закрепление инструмента', f'''
<p>Раньше CLI stdout/stderr перенаправлялись в файлы, а обработчик писал находки только в Actions Summary и artifact. Поэтому при раскрытии шага списка уязвимостей не было. Теперь шаг <b>Evaluate server actions and write Summary</b> выводит каждую Block/Warn находку: пакет, версию, CVE/GHSA, severity, server action и исправленную версию.</p>
<figure>{''.join(svg)}<figcaption>Визуализация точного фрагмента лога, не screenshot интерфейса GitHub. Полный исходник: {link(manifest['run_url']+'/job/128699958991','job log')}.</figcaption></figure>
<p>Monitor/Ignore остаются в JSON, чтобы сохранить доказательства и не переполнять основной лог. Секрет, advisory descriptions и raw HTTP bodies в этот вывод не добавляются.</p>
<h3>Что закреплено</h3>
{table(['Объект','Закрепление'],[['Socket CLI','1.13.1, tarball URL и SHA-512 SRI'],['Весь npm install graph','dependencies.lock, 33 entries с SHA-512 integrity'],['Сам lockfile','SHA-256 перед npm ci'],['GitHub actions','checkout, setup-node и upload-artifact по commit SHA'],['Lifecycle scripts инструмента','Отключены через npm ci --ignore-scripts']])}
<pre class="hash">Socket SRI
sha512-du881tyG17a2TctQEuJDvv5FoAl5zKnSmk2BDmaDbPTLbd64joDeBISppgSS4mhGcL3y3Nvt2pYBLQce6zQ0lg==

Dependency lock SHA-256
8e08f1210ed72a39f14ab565083a228591e50ed9e4716aa5e4d2c3f1fa46c023</pre>
<p>npm проверяет загружаемые пакеты по integrity lockfile; изменение одного байта lockfile отклоняется до установки. Файлы инструмента хранятся под именами <code>package.manifest</code> и <code>dependencies.lock</code>, затем копируются во временный каталог как обычные npm manifests. Инвентарь приложения в тестах остался 1433 компонента.</p>
<p>Full reachability engine дополнительно загружается механизмом Socket CLI. Проверка top-level CLI и npm dependencies сама по себе не является аудитом всех скачиваемых engine/analyzer binaries. Их версию и vendor integrity следует отдельно зафиксировать для требований полностью воспроизводимой analysis toolchain.</p>
'''))

sections.append(('Матрица тестов и решение', f'''
<p>Статусы отражают выполненные проверки, а не предполагаемую поддержку продукта. Реальные API/scan tests, synthetic fixtures и запланированные сценарии разделены.</p>
{table(['ID','Проверка','Тип','Статус'],[[e(c['id']),e(c['name']),e(c['kind']),status[c['status']]] for c in cases if c['id'] not in {x['id'] for x in replay['cases']}])}
<h3>Предлагаемая конфигурация</h3>
<p><b>По умолчанию в PR:</b> manifest scan, generic discovery, server-action gate, читаемый step log, Summary и JSON artifact. <b>Для критичных репозиториев:</b> отдельный opt-in full application reachability; для Voting режим уже прошёл реальный тест. Не включать автоматически полноразмерный анализ во все проекты до измерения времени и подготовки зависимостей.</p>
<p><b>Для организации:</b> центральный защищённый реестр решений и один reusable evaluator. OpenVEX для vulnerability applicability, отдельная модель для accepted risk и остальных типов исключений. Native Socket resolutions можно синхронизировать из этого реестра для dashboard, сохраняя один источник истины.</p>
<p>Текущий выбор — архитектурная рекомендация после ограниченного POC, а не утверждение, что production exclusion management уже готов. Полный native тест заблокирован 403, VEX adapter ограничен npm, live Docker/Aqua соответствия и release gate ещё не проверены.</p>
<h3>Следующие обязательные проверки</h3>
<ol><li>Выдать отдельный repo-scoped resolution test token и выполнить создание, применение на серверном snapshot, отзыв и повторный scan.</li><li>Добавить одно утверждённое собственное решение для реально применимого npm finding, с владельцем и сроком пересмотра. Не переносить synthetic fixture в central feed.</li><li>Подключить trusted central snapshot перед финальным verdict и проверить, что новый PR не может сам себе выдать исключение.</li><li>На отдельном DHI image проверить live Docker/Aqua inputs и конфликты с own feed.</li><li>В release использовать уже выполняемую Docker build, создать runtime SBOM, сканировать immutable digest и продвигать тот же digest после effective gate.</li></ol>
<p>BuildKit SBOM дополняет исходный npm inventory OS-пакетами и runtime. Для build/dev dependencies сохраняется отдельный контекст. Повторная production сборка ради SCA manifests не нужна. В текущем Dockerfile Voting копируется весь /app после yarn install, поэтому runtime image необходимо проверить отдельно.</p>
'''))

sections.append(('Как документировать следующие тесты', f'''
<p>Для каждого сценария сохраняем одну запись в <code>test-results.json</code> и связанные evidence. Повторный тест создаёт новую запись с датой и commit; прежний результат не переписывается как доказательство другого запуска.</p>
{table(['Поле','Что записывать'],[['ID и цель','Например EX-N03 — применение и отзыв native resolution'],['Предусловия','Policy revision, scopes, repository, mode, runner/toolchain'],['Входы','Git commit, image digest/platform, scan ID, VEX document hash и source revision'],['Шаги','Точная команда или workflow input, без секретов'],['Ожидаемый результат','Effective action, ожидаемый exit code, ожидаемые изменения UI'],['Фактический результат','Полученный action/exit, числа findings, время; тип evidence'],['Доказательства','Actions run/job, JSON artifact, фрагмент лога или screenshot с подписью'],['Вывод','Pass, fail, blocked или not run; ограничение и следующий шаг']])}
<h3>Воспроизведение</h3>
<pre>PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \\
  -s .github/scripts/tests -bv

bash .github/scripts/install-socket-cli.sh --verify-only

gh workflow run socket-pr-test.yaml \\
  --ref socket-pr-analysis -f run_reachability=true

python3 .github/scripts/build-socket-poc-report.py</pre>
<h3>Источники и навигация</h3>
<ul><li>{link('https://github.com/myTestOrg0/dao-voting-ui/pull/2','Тестовый PR №2')}</li><li>{link(manifest['run_url'],'Manifest scan и проверка step log')}</li><li>{link(reach['run_url'],'Full application reachability comparison')}</li><li>{link('https://docs.socket.dev/docs/socket-scan','Socket scan reference')}</li><li>{link('https://docs.socket.dev/docs/precomputed-reachability','Precomputed reachability')}</li><li>{link('https://docs.socket.dev/docs/full-application-reachability','Full application reachability')}</li><li>{link('https://docs.socket.dev/docs/alert-resolutions','Socket alert resolutions')}</li><li>{link('https://docs.socket.dev/reference/createorgalertresolution','Resolution create scopes и dry-run contract')}</li><li>{link('https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md','OpenVEX specification')}</li></ul>
<p class="source">Документ подготовлен 8 ноября 2026. Данные измерений привязаны к commit {e(manifest['commit'])}. Документ не содержит API key. Схемы созданы для объяснения архитектуры; визуализация лога подписана отдельно. GitHub artifacts хранятся 7 дней, поэтому компактные evidence сохранены рядом с документом.</p>
'''))

css='''*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#edf1f5;color:#182630;font:16px/1.58 -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}main{max-width:1120px;margin:32px auto 80px;background:white;padding:52px 62px;box-shadow:0 8px 35px #26384a13}header{padding-bottom:25px;border-bottom:1px solid #d8e1e8}h1{font-size:34px;line-height:1.2;margin:10px 0;color:#000}h2{font-size:26px;line-height:1.3;color:#000;margin:0 0 22px}h3{font-size:20px;color:#000;margin:28px 0 12px}p{margin:12px 0}.kicker{font-size:12px;letter-spacing:1.3px;text-transform:uppercase;color:#556574}.subtitle{font-size:18px;color:#506273}.lead{font-size:18px}.meta{font-size:13px;color:#566a7a}nav{display:flex;gap:8px;flex-wrap:wrap;margin:24px 0}nav a{background:#edf4fa;border-radius:5px;padding:6px 10px;font-size:13px}a{color:#17597f;text-decoration:none}a:hover{text-decoration:underline}.page{padding:40px 0 16px;border-bottom:1px solid #dbe3e9;scroll-margin-top:20px}.section-num{color:#617786;font-size:13px;display:block;margin-bottom:9px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.metrics.three{grid-template-columns:repeat(3,1fr)}.metrics>div{background:#eef5f9;border-radius:8px;padding:18px}.metrics b{display:block;font-size:29px;color:#123d58;line-height:1.2}.metrics span{display:block;color:#405768;font-size:13px;margin-top:8px}.note{background:#fff5e4;border-left:4px solid #bf8c37;padding:16px 19px;margin:22px 0}code{font-size:.88em;background:#f1f4f6;padding:2px 4px;border-radius:3px;overflow-wrap:anywhere}pre{background:#f3f6f8;padding:17px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,Menlo,monospace}.hash{font-size:12px}.table-wrap{overflow-x:auto;margin:18px 0 24px}table{border-collapse:collapse;width:100%;font-size:14px;line-height:1.45}th,td{border:1px solid #d9d9d9;padding:11px 12px;text-align:left;vertical-align:middle}th{background:#22475e;color:white;font-weight:600}tr:nth-child(even) td{background:#f4f7fa}td:first-child{font-weight:500}svg{display:block;width:100%;height:auto;margin:18px 0}figure{margin:22px 0}figcaption,.source{font-size:13px;color:#5b6e7c}.badge{font-size:11px;font-weight:600;padding:4px 7px;border-radius:4px;white-space:nowrap}.good{background:#e6f2e8;color:#245f37}.warn{background:#fff0d7;color:#80561c}.muted{background:#e9edf0;color:#536570}li{margin:8px 0}.toolbar{position:fixed;right:20px;bottom:18px}button{background:#244d68;color:white;border:0;border-radius:7px;padding:12px 18px;cursor:pointer}.only main{margin:0;max-width:1120px;box-shadow:none}.only header,.only nav,.only .toolbar{display:none}.only .page{border:none;padding-top:15px}@media(max-width:800px){main{margin:0;padding:25px 22px}.metrics{grid-template-columns:repeat(2,1fr)}h1{font-size:28px}th,td{padding:8px;font-size:12px}}@media print{@page{size:A4;margin:16mm}body{background:white;font-size:10pt;line-height:1.4}main{margin:0;padding:0;max-width:none;box-shadow:none}.toolbar,nav{display:none}h1{font-size:25pt}h2{font-size:19pt}h3{font-size:13pt}p{margin:8px 0}.page{break-before:page;border:0;padding:0}.page:first-of-type{break-before:auto}table{font-size:8.5pt}th,td{padding:7px}tr{break-inside:avoid}figure,.metrics,.note{break-inside:avoid}.metrics b{font-size:21pt}.metrics span,.source,figcaption{font-size:8pt}details{display:block}details>*{display:block}svg{max-height:180px}a{color:#17415e}}'''
nav=''.join(f'<a href="#s{i}">{i:02d} {e(title)}</a>' for i,(title,_) in enumerate(sections,1))
body=''.join(f'<section class="page" id="s{i}"><span class="section-num">{i:02d} / {len(sections):02d}</span><h2>{e(title)}</h2>{content}</section>' for i,(title,content) in enumerate(sections,1))
output=f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Socket Dev POC Варианты интеграции и результаты тестов</title><style>{css}</style></head><body><main><header><div class="kicker">Engineering validation report · 08 ноября 2026</div><h1>Socket Dev POC</h1><p class="subtitle">Варианты интеграции в pull request и управление исключениями</p><p class="meta">myTestOrg0 / dao-voting-ui · Socket lido-labs · read-only GitHub integration</p></header><nav>{nav}</nav>{body}</main><div class="toolbar"><button onclick="window.print()">Печать или PDF</button></div><script>const p=new URLSearchParams(location.search).get('page');if(p){{document.body.classList.add('only');document.querySelectorAll('.page').forEach((s,i)=>{{if(i+1!==Number(p))s.style.display='none'}})}}</script></body></html>'''
(DOCS/'report.html').write_text(output)
print(DOCS/'report.html')
