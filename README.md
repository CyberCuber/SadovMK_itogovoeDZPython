# Automated Threat Monitoring System

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

pip install requests pandas matplotlib

2. Создать тестовые логи:

python create_logs.py

3. Запустить основной скрипт:

python threat_monitor.py


## Результаты работы
- `threat_report.json` - отчет об угрозах
- `threat_analysis.png` - график распределения угроз
- `logs/suricata.json` - проанализированные логи

## Структура проекта
threat_monitor/
+-- threat_monitor.py # основной скрипт
+-- create_logs.py # создание тестовых логов
+-- README.md # документация
+-- logs/ # папка с логами
¦ L-- suricata.json # логи
+-- threat_report.json # отчет (создается)
L-- threat_analysis.png # график (создается)