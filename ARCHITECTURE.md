# ARCHITECTURE – מערכת העברת קבצים מוצפנת

> מסמך התכנון של הפרויקט: כל ההחלטות, המבנה, והתקדמות העבודה.
> הכללים המחייבים מההוראות נמצאים ב-[INSTRUCTIONS.md](INSTRUCTIONS.md).
> **כל שינוי בהחלטה → מעדכנים כאן.**

---

## 1. תמונה כללית

```
┌──────────────── לקוח (C++20) ────────────────┐        TCP / בינארי / LE        ┌──────────── שרת (Python 3.12) ────────────┐
│ transfer.json  me.info  priv.key             │  ───────── בקשות ──────────►    │ port.info                                  │
│ CryptoPP: RSA-1024, AES-256-CBC, cksum       │  ◄──────── תשובות ─────────     │ PyCryptodome: RSA-OAEP, AES-256-CBC, cksum │
│ Winsock                                      │                                 │ threads, זיכרון + תיקיית received_files/   │
└──────────────────────────────────────────────┘                                 └────────────────────────────────────────────┘
```

### רצף מלא של הודעות
```
לקוח                                              שרת
 ┌─ me.info לא קיים ─────────────────────────────────────────┐
 │ 825 רישום (Name) ─────────────────────────►               │
 │ ◄──────────────────── 1600 (ClientID) / 1601              │
 │ [יוצר RSA, שומר me.info + priv.key]                        │
 │ 826 מפתח ציבורי (Name + PubKey 160) ──────►               │
 │ ◄──────────────────── 1602 (ClientID + AES מוצפן)         │
 └───────────────────────────────────────────────────────────┘
 ┌─ me.info קיים ────────────────────────────────────────────┐
 │ 827 התחברות חוזרת (Name) ─────────────────►               │
 │ ◄──────────────────── 1605 (ClientID + AES מוצפן)         │
 │ ◄──────────────────── 1606 → מוחק me.info ונרשם מחדש      │
 └───────────────────────────────────────────────────────────┘
 לכל קובץ ב-files (ניסיון 1..4):
   828 × N חבילות (תוכן מוצפן) ──────────────►
   ◄──────────────────── 1603 (CRC של השרת)
   CRC תואם      → 900 ───►  ◄─── 1604   ✔ קובץ הבא
   לא, ניסיון<4  → 901 ───►  (אין תשובה)  ↻ שולחים 828 שוב
   לא, ניסיון 4  → 902 ───►  ◄─── 1604   ✘ קובץ הבא
```

---

## 2. החלטות תכנון

| # | נושא | החלטה | נימוק |
|---|---|---|---|
| D1 | ריבוי לקוחות בשרת | **thread לכל חיבור** (`threading`) + `Lock` על הנתונים המשותפים | פשוט וקריא יותר מ-selector |
| D2 | Timeout | `socket.settimeout(300)` בשרת (5 דק'). בלקוח timeout קבלה של 60 שניות | דרישה "כ-5 דקות" |
| D3 | המפתח הפרטי | נשמר **בשני המקומות**: שורה 3 ב-`me.info` וגם `priv.key` (Base64). **קוראים מ-`priv.key`** | ההוראות מזכירות את שניהם |
| D4 | JSON בלקוח | **parser קטן שנכתוב בעצמנו** (`JsonParser`). backslash בודד שאינו escape חוקי → נשמר כתו רגיל | אסור ספריות נוספות; הדוגמה בהוראות לא JSON תקין |
| D5 | תשובה ל-901 | **השרת לא עונה** על 901, הלקוח שולח 828 מיד | 1604 מוגדר רק כתשובה ל-900/902 |
| D6 | מספר ניסיונות CRC | שליחה ראשונה + עד **3 שליחות חוזרות** = 4. אחרי כישלון רביעי → 902 | התרשים: "No 4th time → abort" |
| D7 | ניסיונות על שגיאת שרת | שליחה ראשונה + עד **3 חוזרות**. אחרי זה → `Fatal: ...` ויציאה (קוד ≠ 0) | ההוראות |
| D8 | מה נחשב "שגיאה" | 1601, 1607, קוד תשובה לא צפוי, או payload בגודל לא תקין | ההוראות: "בכל מקרה של שגיאה" |
| D9 | חלוקה לחבילות (828) | הלקוח מצפין ומחלק את הטקסט המוצפן לחבילות של **64 KiB** (ברירת מחדל). אם יוצא יותר מ-65535 חבילות – מגדילים את החבילה (מעוגל לכפולה של 16). מספור **מ-1** | שדה Total packets הוא 2 בתים. 64 KiB מקטין את התקורה של כותרת 828 (267 בתים) ל-0.4% לחבילה, ומקטין מספר קריאות send/recv. הזיכרון בשימוש עדיין קטן |
| D10 | גודל מוצפן ידוע מראש | `ContentSize = (OrigSize / 16 + 1) * 16` (PKCS7 תמיד מוסיף padding) | אפשר לשלוח ContentSize כבר בחבילה הראשונה בלי להחזיק את כל הקובץ בזיכרון |
| D11 | קבלת קובץ בשרת | **streaming**: כל חבילה נכתבת לקובץ זמני בדיסק; כשמספר הבתים שהתקבל = ContentSize → מפענחים בבלוקים ומחשבים cksum תוך כדי | הוראות: "הודעה יכולה להיות גדולה מאוד" |
| D12 | גמישות בקבלה (interoperability) | השרת מסיים לפי **סכום הבתים = ContentSize**, ובודק שהמספור עקבי (packet ≤ total, ContentSize/OrigSize/FileName זהים בכל החבילות). לא מניח גודל חבילה קבוע | צריך לעבוד גם מול לקוחות של סטודנטים אחרים |
| D13 | שם קובץ ב-828 | הלקוח שולח **רק את שם הקובץ** (בלי נתיב). השרת **מנקה**: לוקח basename, דוחה `..`, תווים אסורים ושם ריק → 1607 | מניעת path traversal |
| D14 | מיקום שמירה בשרת | `received_files/<client_id_hex>/<file_name>` | אין התנגשות בין לקוחות עם אותו שם קובץ |
| D15 | 902 בשרת | הקובץ **נמחק** מהדיסק ומסומן לא מאומת. 900 → מסומן `verified=True` | לא לשמור קובץ פגום |
| D16 | RSA | CryptoPP: `GenerateRandomWithKeySize(rng, 1024)` (מעריך ברירת מחדל e=17 → DER X.509 של **160 בתים** בדיוק). הצפנה: **OAEP-SHA1** (`RSAES_OAEP_SHA_*` ↔ `PKCS1_OAEP` ב-Python) | תאימות לגודל 160 בפרוטוקול + לדוגמת יחידה 7 |
| D17 | AES | מפתח 32 בתים אקראיים (`get_random_bytes`), CBC, IV = 16 אפסים, padding PKCS7. מוצפן ב-RSA-1024 → 128 בתים | ההוראות |
| D18 | AES לכל חיבור | בכל 826 / 827 נוצר **מפתח AES חדש**, נשמר לאותו לקוח בזיכרון | ההוראות + התרשים |
| D19 | אימות זהות בבקשות | בכל בקשה חוץ מ-825: ClientID חייב להיות רשום, והשם בבקשה (826/827) חייב להתאים לו. 828–902 דורשים שכבר נשלח AES ללקוח | קלט עוין |
| D20 | בדיקת גרסת לקוח | השרת **מקבל כל גרסה** ורק רושם בלוג | interoperability |
| D21 | גבולות גודל | Payload של 825/827/900-902 חייב להיות בדיוק 255; של 826 בדיוק 415; של 828 לפחות 267. `MAX_CONTENT_SIZE` קבוע בשרת (למשל 1 GiB) | הגנה מפני DoS |
| D22 | קבצי הלקוח | נמצאים **בתיקיית ה-exe** (`GetModuleFileNameW`), לא בתיקיית העבודה | ההוראות |
| D23 | 1606 | הלקוח מוחק את `me.info` ו-`priv.key`, ומבצע רישום מלא (825 → 826) | ההוראות |
| D24 | שמירת `me.info` | אחרי 1600: יוצרים RSA → כותבים `me.info` + `priv.key` → שולחים 826 | אם 826 נכשל, המפתחות כבר שמורים |
| D25 | סריאליזציה בלקוח | פונקציות עזר `writeU16LE / writeU32LE / readU32LE` עם הזזות ביטים. **אין** `memcpy` של struct ו**אין** `#pragma pack` | Intel ו-ARM |
| D26 | חיבור אחד | הלקוח פותח **חיבור TCP אחד** לכל הריצה ושולח בו את כל הקבצים | פשוט, מתאים לתרשים |
| D27 | לוגים | שרת: מודול `logging` למסך. לקוח: הודעות התקדמות ל-`std::cout`, שגיאות ל-`std::cerr` | מעקב + הסרטון |
| D28 | בונוס SQLite | **נדחה לסוף.** שכבת האחסון בשרת (`ClientStore`) בנויה כך שאפשר להוסיף לה DB בלי לשנות את שאר הקוד | החלטת המשתמשת |
| D29 | היררכיית חריגות בלקוח | קובץ `Errors.h`: בסיס `ClientError : std::runtime_error`, ומתחתיו: **`ServerError`** (1601, 1607, קוד לא צפוי, payload בגודל שגוי) → **ניסיון חוזר** לפי D7, עם ההודעה `server responded with an error`; **`ProtocolError`** (תשובה פגומה שאי אפשר לפענח, למשל גרסה/כותרת שבורה) → נחשב גם הוא לשגיאת שרת ועובר ניסיון חוזר; **`FatalError`** (קובץ קונפיגורציה חסר/פגום, כשל חיבור, חיבור שנסגר, קובץ לקוח לא קריא, מיצוי ניסיונות) → יציאה מיידית. `main.cpp` תופס `FatalError` (וכל `std::exception`) ומדפיס `Fatal: <פירוט>` | ההבחנה בין "לנסות שוב" ל"לצאת" חייבת להיות מפורשת בקוד |
| D30 | קבועים בלקוח | קובץ `Constants.h` עם `constexpr` בלבד: גרסה, כל קודי הבקשות והתשובות (`enum class`), כל גדלי השדות, גודל כותרות, גודל חבילה, מספר ניסיונות, timeouts, שמות קבצים (`transfer.json`, `me.info`, `priv.key`), גדלי מפתחות. **אף מספר לא מופיע ישירות בקוד** | הוראות: "המנעו ממספרי קסם" |
| D31 | Visual Studio 2026 | הפרויקט נבנה ונבדק ב-**VS Community 2026**, עם `/std:c++20` מוגדר במפורש (Project → Properties → C/C++ → Language), גם ב-Debug וגם ב-Release, x64. VS 2022 משמש רק עד שתהיה התקנה של 2026 | זו סביבת הבדיקה של המטלה |

---

## 3. מבנה תיקיות

```
דפנסיבי/
├── INSTRUCTIONS.md          כללי המטלה
├── ARCHITECTURE.md          המסמך הזה
├── CLAUDE.md                הפניה לשני הקבצים (ל-Claude)
├── server/                  ← מוגש (רק .py)
│   ├── server.py            main(), לולאת accept, thread לכל לקוח
│   ├── config.py            קריאת port.info
│   ├── protocol.py          קבועים, קודים, pack/unpack
│   ├── session.py           ClientSession – טיפול בחיבור אחד
│   ├── client_store.py      ClientRecord, FileRecord, ClientStore (בזיכרון, עם Lock)
│   ├── crypto_utils.py      AES/RSA
│   ├── cksum.py             CRC בסגנון cksum של לינוקס
│   ├── port.info            (לא מוגש – רק לבדיקה)
│   └── tests/               (לא מוגש) test_client.py, בדיקות יחידה
├── client/                  ← מוגש (רק .h/.cpp)
│   ├── main.cpp             נקודת כניסה, try/catch → Fatal
│   ├── Constants.h          כל הקבועים (constexpr) – D30
│   ├── Errors.h             ClientError / ServerError / ProtocolError / FatalError – D29
│   ├── Endian.h             writeU16LE / readU32LE ...
│   ├── Protocol.h/.cpp      בניית בקשות, פענוח תשובות (משתמש ב-Constants.h)
│   ├── JsonParser.h/.cpp    parser מינימלי
│   ├── TransferConfig.h/.cpp  קריאה ובדיקה של transfer.json
│   ├── ClientIdentity.h/.cpp  me.info + priv.key
│   ├── RsaWrapper.h/.cpp    יצירה, ייצוא, פענוח (CryptoPP)
│   ├── AesWrapper.h/.cpp    הצפנה בבלוקים (CryptoPP)
│   ├── Base64.h/.cpp
│   ├── Cksum.h/.cpp
│   ├── TcpConnection.h/.cpp sendAll / recvExact (Winsock, RAII)
│   ├── FileTransferClient.h/.cpp  הזרימה הראשית (state machine)
│   └── tests/               (לא מוגש) פונקציות בדיקה קטנות
└── docs/
    ├── unit7/               קוד הדוגמה מיחידה 7 (cksum + CryptoPP)
    └── Q2_vulnerabilities   מסמך שאלה 2
```

---

## 4. שרת – מחלקות ואחריות

| מודול | מחלקה / פונקציה | אחריות |
|---|---|---|
| `config.py` | `read_port() -> int` | קורא `port.info`; חסר/לא תקין → אזהרה + 1369 |
| `protocol.py` | `RequestCode`, `ResponseCode` (IntEnum), `RequestHeader`, `build_response()` | כל הגדלים והקודים כקבועים. `struct` עם `<` (little endian): כותרת בקשה `"<16sBHI"`, כותרת תשובה `"<BHI"` |
| `cksum.py` | `Cksum` (`update(bytes)`, `digest(total_len)`) | CRC מצטבר, זהה ל-`cksum` |
| `crypto_utils.py` | `generate_aes_key()`, `encrypt_aes_key(pub_der, key)`, `AesCbcStreamDecryptor` | הצפנה ופענוח |
| `client_store.py` | `ClientRecord`, `FileRecord` (dataclass), `ClientStore` | רישום, חיפוש לפי שם / ID, עדכון מפתחות, רשימת קבצים. כל פעולה תחת `Lock` |
| `session.py` | `ClientSession` | `recv_exact`, קריאת כותרת, ניתוב לפי קוד (`_handle_register`, `_handle_public_key`, `_handle_reconnect`, `_handle_file`, `_handle_crc_*`), תפיסת חריגות → 1607 |
| `server.py` | `Server`, `main()` | bind/listen, accept בלולאה אינסופית, thread לכל חיבור |

**עקרון:** כל חריגה בתוך session נתפסת, נרשמת בלוג, ומחזירה 1607 (או סוגרת חיבור אם הכותרת עצמה פגומה). השרת הראשי לעולם לא נופל.

---

## 5. לקוח – מחלקות ואחריות

| מחלקה | אחריות | תלויות |
|---|---|---|
| `Constants` | כל הגדלים, הקודים, הגרסה, ה-timeouts ושמות הקבצים | – |
| `Errors` | טיפוסי חריגות: מה מנסים שוב ומה יוצא ב-Fatal | – |
| `Endian` | המרת מספרים ל/מ little endian | – |
| `JsonParser` | פענוח JSON מינימלי (object, array, string, number) | – |
| `TransferConfig` | IP, פורט (1–65535), שם (1–100 תווי ASCII), רשימת קבצים לא ריקה | JsonParser |
| `ClientIdentity` | קריאה וכתיבה של `me.info` / `priv.key` עם בדיקות (32 תווי hex, Base64 תקין) | Base64 |
| `Base64` | קידוד / פענוח | CryptoPP |
| `RsaWrapper` | יצירת זוג 1024, ייצוא ציבורי (160), ייצוא/ייבוא פרטי, פענוח OAEP | CryptoPP |
| `AesWrapper` | AES-256-CBC, IV אפס, הצפנה בבלוקים | CryptoPP |
| `Cksum` | CRC מצטבר זהה ל-`cksum` | – |
| `Protocol` | בניית בקשות (bytes), פענוח כותרת ו-payload של תשובות | Endian |
| `TcpConnection` | connect / sendAll / recvExact, ‏RAII על `SOCKET` ו-`WSAStartup` | Winsock |
| `FileTransferClient` | הזרימה המלאה: רישום / התחברות חוזרת, קבלת AES, שליחת קבצים, CRC, ניסיונות חוזרים | כל השאר |

**עקרון:** כל מחלקה ניתנת לבדיקה בנפרד. רק `FileTransferClient` מחבר ביניהן.

---

## 6. מבנה בתים מדויק (לבדיקות)

| הודעה | גודל payload |
|---|---|
| 825 / 827 / 900 / 901 / 902 | 255 |
| 826 | 255 + 160 = 415 |
| 828 | 4 + 4 + 2 + 2 + 255 = 267 + גודל החבילה |
| 1600 / 1604 / 1606 | 16 |
| 1602 / 1605 | 16 + 128 = 144 |
| 1603 | 16 + 4 + 255 + 4 = 279 |
| 1601 / 1607 | 0 |

שדות מחרוזת (Name / File Name): 255 בתים, ריפוד באפסים, **לפחות בית null אחד** → אורך מקסימלי בפועל 254 תווים.

---

## 7. סביבת עבודה – מצב נוכחי (נבדק 17.10.2026)

| רכיב | מצב | מה לעשות |
|---|---|---|
| Python | 3.13.5 מותקן | להתקין **3.12** (הגרסה הקובעת) ולעבוד איתה |
| PyCryptodome | ❌ לא מותקן | `pip install pycryptodome` |
| ruff | ✅ 0.16.7 | – |
| Visual Studio | Community **2022** | הבדיקה ב-**2026** – להתקין VS Community 2026 עם workload "Desktop development with C++" (D31) |
| CryptoPP | ❌ לא נמצא | התקנה דרך vcpkg (ראו למטה) |
| `cksum` | ✅ ב-Git Bash | משמש לבדיקת ה-CRC |
| git | ✅ מאגר נפרד בתיקיית הפרויקט, ענף `main` | – |

### התקנת CryptoPP (vcpkg)
```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cryptopp:x64-windows
C:\vcpkg\vcpkg integrate install
```
אחרי זה Visual Studio מוצא אוטומטית `#include <cryptopp/rsa.h>` ואת קובץ ה-lib.
**לבדוק:** איך קוד הדוגמה של יחידה 7 עושה include, ולהתאים.

---

## 8. מעקב התקדמות

סימון: ⬜ לא התחלנו · 🟨 בעבודה · ✅ עובד ונבדק

### שלב 0 – סביבה
| # | משימה | בדיקה | מצב |
|---|---|---|---|
| 0.1 | מאגר git בתיקיית הפרויקט + `.gitignore` | `git status` | ✅ (github.com/Ayala679/secure-file-transfer) |
| 0.2 | Python 3.12 + pycryptodome | `python -c "import Crypto"` | ⬜ |
| 0.3 | vcpkg + CryptoPP | פרויקט Hello World שמצפין מחרוזת ב-AES | ⬜ |
| 0.4 | להעתיק את קוד הדוגמה של יחידה 7 ל-`docs/unit7/` | – | ⬜ |
| 0.5 | VS Community 2026 + פרויקט עם `/std:c++20` | פרויקט Hello World מתקמפל ב-2026 עם CryptoPP | ⬜ |

### שלב 1 – שרת
| # | משימה | בדיקה | מצב |
|---|---|---|---|
| S1 | `config.py` | קובץ חסר / ריק / טקסט / פורט 0 או 70000 | ⬜ |
| S2 | `protocol.py` | גדלי כותרות 23/7, pack→unpack זהה | ⬜ |
| S3 | `cksum.py` | זהה ל-`cksum` של Git Bash על 3+ קבצים (כולל ריק) | ⬜ |
| S4 | `crypto_utils.py` | round-trip RSA + AES בתוך Python | ⬜ |
| S5 | `client_store.py` | רישום כפול נדחה, חיפוש לפי ID | ⬜ |
| S6 | `session.py` – רק 825 | `test_client.py` נרשם ומקבל 1600, שם כפול → 1601 | ⬜ |
| S7 | 826 + 827 | מקבלים AES מוצפן ומפענחים בצד הבדיקה | ⬜ |
| S8 | 828 (חבילות) + 900/901/902 | קובץ 100KB עובר, CRC תואם, הקובץ שמור | ⬜ |
| S9 | `server.py` – threads + timeout | 3 לקוחות במקביל | ⬜ |
| S10 | קלט זדוני | גודל ענק, קוד לא מוכר, שם `../x`, חיבור שנסגר באמצע → השרת ממשיך | ⬜ |
| S11 | ruff נקי | `ruff check server` | ⬜ |

### שלב 2 – לקוח
| # | משימה | בדיקה | מצב |
|---|---|---|---|
| C0 | `Constants.h` + `Errors.h` | מתקמפל; אין מספרים ישירים בשאר הקוד | ⬜ |
| C1 | `Endian` + `Protocol` | בתים זהים ל-`protocol.py` | ⬜ |
| C2 | `JsonParser` + `TransferConfig` | הדוגמה מההוראות + קבצים שבורים | ⬜ |
| C3 | `Base64` + `ClientIdentity` | כתיבה → קריאה → השוואה | ⬜ |
| C4 | `Cksum` | זהה ל-`cksum` ול-Python | ⬜ |
| C5 | `RsaWrapper` | ציבורי = 160 בתים; Python מצפין → C++ מפענח | ⬜ |
| C6 | `AesWrapper` | C++ מצפין → Python מפענח | ⬜ |
| C7 | `TcpConnection` | שליחה וקבלה מול השרת | ⬜ |
| C8 | `FileTransferClient` – רישום / התחברות חוזרת | ריצה ראשונה → 1600+1602; ריצה שנייה → 1605 | ⬜ |
| C9 | שליחת קבצים + CRC + ניסיונות חוזרים | 100KB, קובץ ריק, 10MB, כמה קבצים | ⬜ |
| C10 | מקרי קצה | קובץ לא קיים, שרת כבוי, 1606, `me.info` פגום | ⬜ |

### שלב 3 – סיום
| # | משימה | מצב |
|---|---|---|
| F1 | שאלה 2 – מסמך חולשות (טבלה בפורמט יחידה 3) | ⬜ |
| F2 | בנייה מחדש בתיקייה נקייה + פרויקט VS חדש (רצוי VS 2026) | ⬜ |
| F3 | הקלטת וידאו | ⬜ |
| F4 | zip להגשה | ⬜ |
| B1 | ⏸️ בונוס SQLite – רק אם נשאר זמן | ⬜ |
