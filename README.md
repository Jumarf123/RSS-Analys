# RSS-Analys

<p align="center">
  <a href="#ru"><img alt="Русский" src="https://img.shields.io/badge/Русский-Read-1f6feb?style=for-the-badge" /></a>
  <a href="#en"><img alt="English" src="https://img.shields.io/badge/English-Read-1f6feb?style=for-the-badge" /></a>
</p>

<p align="center">
  <a href="https://github.com/Jumarf123/RSS-Analys/releases/download/1.0/RSS-Analys.exe">
    <img alt="Download RSS-Analys" src="https://img.shields.io/badge/Скачать%20%2F%20Download-RSS--Analys.exe-2ea043?style=for-the-badge&logo=github&logoColor=white" />
  </a>
</p>


<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Platform-Windows-2ea043?style=flat-square" />
  <img alt="Rust" src="https://img.shields.io/badge/Built%20with-Rust-b7410e?style=flat-square" />
  <img alt="Reports" src="https://img.shields.io/badge/Output-TXT%20%2B%20HTML-8250df?style=flat-square" />
  <img alt="Use case" src="https://img.shields.io/badge/Use%20Case-Minecraft%20Screenshare-0969da?style=flat-square" />
</p>

<p align="center">
  Практичный инструмент для <b>Minecraft screenshare</b>: меньше мусора, больше полезных артефактов, быстрее ручной разбор.
</p>

<p align="center">
  <a href="https://discord.gg/residencescreenshare">
    <img alt="Discord - Residence Screenshare" src="https://img.shields.io/badge/Discord-Residence%20Screenshare-5865F2?style=for-the-badge&logo=discord&logoColor=white" />
  </a>
</p>

---

## Navigation

- [Русский](#ru)
- [English](#en)

---

<a name="ru"></a>
## Русский

### Что это

`RSS-Analys` анализирует `.txt` и `.dmp` (один файл или целую папку), вытаскивает потенциально важные строки, нормализует пути и собирает структурированные результаты в `Results/*` + интерактивный `report.html`.

### Зачем

Когда в дампе много шума, вручную легко пропустить важное. Цель инструмента — быстро отделить артефакты, которые реально стоит проверить.

### Ключевые возможности

- Анализ всех найденных `.txt`/`.dmp` во входном пути
- Нормализация путей (`\??\`, `\Device\HarddiskVolumeN`, «склеенные» строки)
- Классификация PE-артефактов:
  - `allpe` (найдено на диске)
  - `NormalPE` (совпало со встроенным SHA-256 allowlist)
  - `notfound` (не найдено)
- Поиск и статус для:
  - `scripts` (`.ps1`, `.cmd`, `.bat`)
  - `Start` (явно запущенные файлы)
  - `Prefetch` (`*.pf` + статус `no deleted` / `program deleted` / `prefetch missing`)
  - `DPS` (строки формата `!!FILE!value!`)
- Отдельный список `otherdisk` для путей вне базовых локальных дисков (`C/D`)
- Сканирование по встроенным правилам для целевых PE
- HTML-отчёт: вкладки, поиск, RU/EN, светлая/тёмная тема

### Требования

- Windows

### Быстрый старт


Запуск:

```powershell
.\RSS-Analys.exe
```

Далее программа попросит:

1. Язык интерфейса (`1/2`)
2. Нужна ли сортировка хешей (`1/2`)
3. Путь к `.txt`, `.dmp` или папке

После завершения результаты будут в папке рядом с `.exe`:

```text
Results
```

### Карта результатов

| Путь | Что внутри |
|---|---|
| `Results/report.html` | Основной визуальный отчёт |
| `Results/summary/summary.txt` | Короткая сводка по запуску |
| `Results/allpe/allpe.txt` | Подтверждённые `exe/dll` |
| `Results/NormalPE/NormalPE.txt` | Файлы из встроенного normal SHA-256 списка |
| `Results/notfound/full_paths_not_found.txt` | Пути, которые не подтвердились |
| `Results/notfound/files_without_path_not_found.txt` | Имена без пути, не найденные на ПК |
| `Results/allpe/files_without_path.txt` | Имена без пути, которые удалось резолвить |
| `Results/scripts/scripts.txt` | `ps1/cmd/bat` + статус |
| `Results/Start/Start.txt` | Запущенные файлы + статус |
| `Results/Prefetch/Prefetch.txt` | Prefetch + связанная программа + статус |
| `Results/DPS/DPS.txt` | DPS-строки (`Файл | Значение | статус`) |
| `Results/deleted/deleted.txt` | Всё, что отмечено как удалённое/не найденное |
| `Results/otherdisk/otherdisk.txt` | Артефакты с неосновных дисков |
| `Results/yara/yaradetect.txt` | Срабатывания правил сканирования |
| `Results/links/links.txt` | Найденные ссылки |
| `Results/suspend_links/suspend_links.txt` | Подозрительные ссылки |
| `Results/suspect_file/suspect_file.txt` | Подозрительные файлы по словарю |
| `Results/ioc/command_ioc.txt` | Командные IOC |


### Discord

- **Residence Screenshare:** https://discord.gg/residencescreenshare

### Важно

Используйте инструмент только там, где у вас есть явное право проверять систему и данные.

---

<a name="en"></a>
## English

### What it is

`RSS-Analys` processes `.txt` and `.dmp` input (single file or full folder), extracts useful artifacts, normalizes noisy paths, and writes structured output to `Results/*` plus an interactive `report.html`.

### Why it exists

Dump-heavy investigations are noisy. The tool is focused on surfacing what is actually worth reviewing.

### Core capabilities

- Scans all discovered `.txt`/`.dmp` files in the input path
- Normalizes paths (`\??\`, `\Device\HarddiskVolumeN`, chained/broken strings)
- Splits PE artifacts into:
  - `allpe` (confirmed on disk)
  - `NormalPE` (matched against embedded SHA-256 allowlist)
  - `notfound` (unresolved)
- Dedicated tracking for:
  - `scripts` (`.ps1`, `.cmd`, `.bat`)
  - `Start` (explicit process start artifacts)
  - `Prefetch` (`*.pf` with `no deleted` / `program deleted` / `prefetch missing`)
  - `DPS` rows (`!!FILE!value!` format)
- `otherdisk` list for artifacts outside primary local disks (`C/D`)
- Embedded-rule scanning over target PE files
- HTML report: tabs, search, RU/EN, dark/light theme

### Requirements

- Windows

### Quick start

Run:

```powershell
.\RSS-Analys.exe
```

Then follow prompts for language, hash sorting mode, and input path.

### Output map

| Path | Purpose |
|---|---|
| `Results/report.html` | Main visual report |
| `Results/summary/summary.txt` | Run summary |
| `Results/allpe/allpe.txt` | Confirmed `exe/dll` files |
| `Results/NormalPE/NormalPE.txt` | Files matched by embedded normal SHA-256 |
| `Results/notfound/full_paths_not_found.txt` | Unresolved full paths |
| `Results/notfound/files_without_path_not_found.txt` | Unresolved pathless names |
| `Results/allpe/files_without_path.txt` | Resolved pathless names |
| `Results/scripts/scripts.txt` | Script files + status |
| `Results/Start/Start.txt` | Started files + status |
| `Results/Prefetch/Prefetch.txt` | Prefetch rows + program resolution status |
| `Results/DPS/DPS.txt` | DPS rows (`File | Value | status`) |
| `Results/deleted/deleted.txt` | Deleted/missing artifacts |
| `Results/otherdisk/otherdisk.txt` | Non-primary disk artifacts |
| `Results/yara/yaradetect.txt` | Rule detections |
| `Results/links/links.txt` | Extracted links |
| `Results/suspend_links/suspend_links.txt` | Suspicious links |
| `Results/suspect_file/suspect_file.txt` | Suspicious files by keyword set |
| `Results/ioc/command_ioc.txt` | Command IOC |

### Legal note

Use only where you have explicit permission to inspect systems and data.

### Community

- **Residence Screenshare:** https://discord.gg/residencescreenshare
