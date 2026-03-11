[![Typing SVG](https://readme-typing-svg.herokuapp.com?color=%2336BCF7&lines=Automated+science+Monitoring+System)](https://git.io/typing-svg)

## Описание проекта
Автоматизированная система мониторинга и реагирования на угрозы безопасности. 
Проект выполнен в рамках итогового домашнего задания по курсу Python.

## Функциональность
- Анализ логов Suricata
- Проверка IP-адресов через VirusTotal API
- Поиск уязвимостей через Vulners API
- Автоматическое реагирование на угрозы (блокировка IP)
- Формирование отчета в JSON
- Визуализация результатов в PNG

## Используемые технологии
- Python 3.8+
- requests, pandas, matplotlib
- VirusTotal API, Vulners API

## Установка и запуск
1. Установить библиотеки:
`pip install requests pandas matplotlib`
2. Создать тестовые логи:
`python create_logs.py`
3. Запустить основной скрипт:
`python threat_monitor.py`

## Результаты работы
- `threat_report.json` - отчет об угрозах
- `threat_analysis.png` - график распределения угроз
- `logs/suricata.json` - проанализированные логи

## 🗂️ Структура проекта

```ascii
📦 threat_monitor
 ┣━━ 📜 threat_monitor.py       🔍 Основной скрипт мониторинга
 ┣━━ 📜 create_logs.py          🛠️  Генератор тестовых логов
 ┣━━ 📜 README.md                📄 Документация
 ┣━━ 📁 logs/                    📂 Папка с логами
 ┃    ┗━━ 📜 suricata.json       📊 Тестовые логи (50 записей)
 ┣━━ 📜 threat_report.json       📋 Отчет (26 угроз)
 ┗━━ 📜 threat_analysis.png      📈 График распределения угроз


