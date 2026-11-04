# AuthLab — СӨЖ 2 (3 студенттің ортақ жобасы)

**Тақырып:** Веб-қосымшалардағы аутентификация, сессияларды басқару және қол жеткізуді бақылау қауіпсіздігін талдау.

Python 3.11+ стандартты кітапханасымен жұмыс істейтін **жергілікті оқу прототипі**. Интернетке жариялауға арналмаған.

## Үш студенттің жұмысы

| Студент | Құжат | Негізгі код | Тақырыбы |
|---|---|---|---|
| 1 | `docs/1_student_authentication.md` | `authlab/authentication.py` | Login, пароль, PBKDF2, бұғаттау |
| 2 | `docs/2_student_sessions.md` | `authlab/sessions.py` | Session, CSRF, cookie, timeout, logout |
| 3 | `docs/3_student_authorization_tests.md` | `authlab/authorization.py`, `tests/test_authlab.py` | RBAC, IDOR, 17 тест |

`authlab.py` — үш бөлімді біріктіріп, браузер арқылы іске қосатын негізгі сервер. Бұл **үш бөлек веб-сайт емес**, үш студент жазатын бір ортақ жоба.

## Жұмысты іске қосу

Терминал осы README файлы тұрған қалтада ашылсын.

```bash
python authlab.py init
python authlab.py add-user --username alice --role student
python authlab.py add-user --username bob --role student
python authlab.py add-user --username teacher --role teacher
python authlab.py serve
```

`add-user` кезінде әр қолданушыға **кемі 8 таңбалы құпиясөзді** өзіңіз енгізіңіз. Сайтты браузерден ашыңыз: **http://127.0.0.1:8000/login**.

Тесттерді іске қосу:

```bash
python -m unittest discover -s tests -v
```

Әдепкіде PBKDF2 600 000 итерация; оқу тесттерін тез жүргізу үшін (тек тестке арналған ортада) келесі команданы қолдануға болады:

```bash
# macOS / Linux
AUTHLAB_PBKDF2_ITERATIONS=2000 python -m unittest discover -s tests -v
# Windows PowerShell
$env:AUTHLAB_PBKDF2_ITERATIONS='2000'; python -m unittest discover -s tests -v
```

## Қорғауда көрсету

1. `alice` жүйеге кіріп, жазба қосады.
2. `bob` сол жазбаның `/notes/1` сияқты URL-ін ашқанда **404** алады.
3. Студент `/admin/users` кірсе **403**, оқытушы кірсе **200** алады.
4. `logout` жасағаннан кейін бұрынғы сессиямен кіру мүмкін емес.
5. Тесттерді орындап, `Ran 17 tests ... OK` қорытындысын көрсетіңіз.

## Қауіпсіздік шекарасы

Жобада параметрленген SQLite, salted PBKDF2, HttpOnly/SameSite cookie, серверлік session, CSRF, RBAC, owner_id, HTML escape, CSP бар. Демо `127.0.0.1` адресінде ғана жұмыс істейді. HTTPS режиміндегі Secure cookie қасиеті тестпен расталады, бірақ осы оқу сервері TLS қызметін өзі іске асырмайды. Өндіріс үшін HTTPS reverse proxy, MFA, аудит және кеңейтілген тексерістер қажет.

**Ескерту:** `.sqlite3` дерекқор файлын GitHub-қа жарияламаңыз; ол `.gitignore` ішіне енгізілген. Құпиясөздерді README-ге жазбаңыз.
