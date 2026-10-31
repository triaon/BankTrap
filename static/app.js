const $ = id => document.getElementById(id);
const session = crypto.randomUUID();
const sql = "admin' OR '1'='1";
let token = '', state = null, busy = false, lastRender = '';

const eventNames = {
  'SQLi attempt': 'Попытка SQLi', 'Decoy account used': 'Вход с учёткой-приманкой',
  'Demo login': 'Вход в приложение', 'Failed login': 'Ошибка входа',
  'Password guessing': 'Подбор пароля', 'Decoy admin accessed': 'Доступ к админке',
  'Synthetic transfer': 'Тестовый перевод', 'Rule drafted': 'Правило создано',
  'Replay completed': 'Проверка завершена', 'Test rule enabled': 'Правило включено',
  'Test rule disabled': 'Правило отключено', 'Gateway blocked': 'Запрос заблокирован',
  'Gateway passed': 'Запрос пропущен'
};
const sourceNames = {honeypot: 'Приманка', control: 'Оператор', gateway: 'Шлюз'};

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {'Content-Type': 'application/json', 'X-Operator-Token': token, 'X-Demo-Session': session},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await response.json();
  if (data.error) throw Error(data.error);
  return {status: response.status, ...data};
}

function say(text, error = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', error);
}

async function act(id, fn) {
  if (busy) return;
  busy = true;
  $(id).disabled = true;
  try {
    await fn();
    if (token) await refresh();
  } catch (e) {
    say(e.message, true);
  } finally {
    busy = false;
    $(id).disabled = false;
  }
}

function bind(id, fn) { $(id).addEventListener('click', () => act(id, fn)); }

function renderEvents(events) {
  const feed = $('events');
  feed.replaceChildren();
  if (!events.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 5;
    cell.className = 'empty';
    cell.textContent = 'Событий пока нет. Выполните вход или отправьте запрос в шлюз.';
    row.append(cell);
    feed.append(row);
    return;
  }
  for (const event of events) {
    const row = document.createElement('tr');
    const cells = [
      new Date(event.timestamp).toLocaleTimeString('ru-RU'),
      eventNames[event.kind] || event.kind,
      sourceNames[event.source] || event.source,
      event.technique || '—',
      event.detail
    ];
    for (const value of cells) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    feed.append(row);
  }
}

async function refresh() {
  state = await api('/control/state');
  $('connection').textContent = 'SOC подключён';
  $('connection').classList.add('connected');
  const signature = JSON.stringify(state);
  if (signature === lastRender) return;
  lastRender = signature;
  $('count').textContent = state.events.length;
  $('mode').textContent = state.enabled ? 'Правило включено в шлюзе' : 'Правило выключено';
  $('mode').classList.toggle('enabled', state.enabled);
  $('rule').textContent = state.rule ? JSON.stringify(state.rule, null, 2) : 'Правило ещё не создано.';
  $('rule-name').textContent = state.rule ? `${state.rule.id} · версия ${state.rule.version}` : 'Нет правила';
  $('rule-description').textContent = state.rule
    ? `POST /api/auth/login · поле username · событие №${state.rule.evidence_event_id}`
    : 'Отправьте SQLi-запрос в приманку, затем создайте кандидат.';
  $('rule-state').textContent = state.validation
    ? (state.validation.passed ? 'Проверено на тестовом наборе' : 'Проверка не пройдена')
    : state.rule ? 'Черновик' : 'Не создано';
  renderEvents(state.events);
  $('metrics').replaceChildren();
  if (state.validation) {
    const names = {TP: 'Обнаружено', FN: 'Пропущено', FP: 'Ложных блокировок', TN: 'Обычных пропущено'};
    for (const key of ['TP', 'FN', 'FP', 'TN']) {
      const box = document.createElement('div');
      box.className = 'metric';
      box.title = key;
      const n = document.createElement('strong');
      n.textContent = state.validation[key];
      box.append(n, document.createTextNode(names[key]));
      $('metrics').append(box);
    }
    $('limitations').textContent = 'Проверка ' + (state.validation.passed ? 'пройдена. ' : 'не пройдена. ')
      + 'AND/time-based SQLi пропускаются; SQL-фраза в логине может блокироваться. Для пилота нужен отдельный набор банка.';
  } else {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'Проверка ещё не запускалась.';
    $('metrics').append(empty);
    $('limitations').textContent = 'Тестовый набор: 8 атак и 12 обычных запросов. Результат относится только к этому набору.';
  }
}

bind('connect', async () => {
  token = $('token').value.trim();
  await refresh();
  $('access').open = false;
  say('Подключено. Можно отправлять запросы и проверять правила.');
});
bind('reset', async () => {
  await api('/control/reset', {});
  $('bank-result').textContent = 'Вход ещё не выполнен.';
  $('gateway-result').textContent = 'Запрос ещё не отправлен.';
  $('gateway-result').className = 'result neutral';
  say('События и правило сброшены.');
});
bind('sqli', async () => { $('username').value = sql; $('password').value = 'demo'; say('Запрос подставлен. Нажмите «Войти».'); });
bind('canary', async () => { $('username').value = 'demo-admin'; $('password').value = 'demo-canary'; say('Учётная запись подставлена. Нажмите «Войти».'); });
$('login-form').addEventListener('submit', event => {
  event.preventDefault();
  act('login', async () => {
    const result = await api('/api/auth/login', {username: $('username').value, password: $('password').value});
    $('bank-result').textContent = result.ok ? 'Вход выполнен. Баланс: 125 000 DEMO' : 'Вход отклонён.';
    say(result.ok ? 'Вход зарегистрирован.' : 'Неудачная попытка входа зарегистрирована.');
  });
});
bind('brute', async () => {
  for (let i = 0; i < 5; i++) await api('/api/auth/login', {username: 'unknown', password: 'demo-wrong'});
  say('Зарегистрированы пять неудачных попыток входа.');
});
bind('admin', async () => {
  const result = await api('/api/admin/users');
  $('bank-result').textContent = JSON.stringify(result.users, null, 2);
  say('Обращение к админке записано в журнал.');
});
bind('transfer', async () => {
  const result = await api('/api/transfer', {amount: 1000});
  $('bank-result').textContent = result.message;
  say('Тестовый перевод записан в журнал.');
});
for (const [id, endpoint, message] of [
  ['generate', 'generate', 'Создан черновик правила.'],
  ['validate', 'validate', 'Проверка завершена. Результаты показаны в разделе правила.'],
  ['activate', 'activate', 'Правило включено в шлюзе.'],
  ['disable', 'disable', 'Правило отключено.']
]) bind(id, async () => { await api('/control/' + endpoint, {}); say(message); });

async function gateway(username) {
  const result = await api('/gateway/login', {username, password: 'demo'});
  $('gateway-result').textContent = `HTTP ${result.status} · ${result.blocked ? 'ЗАБЛОКИРОВАНО' : 'ПРОПУЩЕНО'}\n${username}`;
  $('gateway-result').className = 'result ' + (result.blocked ? 'warn' : 'ok');
  say(result.blocked ? 'Шлюз заблокировал запрос.' : 'Шлюз пропустил запрос.');
}
bind('attack-gateway', () => gateway(sql));
bind('normal-gateway', () => gateway("o'reilly"));
bind('download', async () => {
  await refresh();
  const blob = new Blob([JSON.stringify({exported_at: new Date().toISOString(), ...state}, null, 2)], {type: 'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'banktrap-evidence.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  say('Отчёт скачан.');
});
setInterval(() => {
  if (token && !busy) refresh().catch(error => {
    $('connection').textContent = 'Нет подключения';
    $('connection').classList.remove('connected');
    say(error.message, true);
  });
}, 1000);
