import requests
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import os
import time
import ssl
import urllib3
# Отключаем предупреждения о SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Создаем контекст SSL, который не проверяет сертификаты
ssl._create_default_https_context = ssl._create_unverified_context

class ThreatMonitor:
    def __init__(self, virustotal_key, vulners_key):
        """
        Инициализация монитора угроз
        
        Args:
            virustotal_key: ключ VirusTotal
            vulners_key: ключ Vulners
        """
        self.vt_key = virustotal_key
        self.vulners_key = vulners_key
        self.threats = []  # список найденных угроз
        self.blocked_ips = []  # список заблокированных IP
        
        # URL для API
        self.vt_url = "https://www.virustotal.com/api/v3"
        self.vulners_url = "https://vulners.com/api/v3/search/lucene/"
        
        # Заголовки для VirusTotal
        self.vt_headers = {
            "x-apikey": self.vt_key,
            "Accept": "application/json"
        }
        
        print("Монитор угроз инициализирован")
    
    def check_ip_virustotal(self, ip):
        """
        Проверка IP через VirusTotal
        
        Args:
            ip: IP адрес для проверки
        """
        try:
            # Ждем 15 секунд между запросами (бесплатный тариф)
            time.sleep(15)
            
            url = f"{self.vt_url}/ip_addresses/{ip}"
            # Добавлен параметр verify=False для отключения проверки SSL
            response = requests.get(url, headers=self.vt_headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                result = {
                    'ip': ip,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': stats.get('harmless', 0)
                }
                
                if malicious > 0 or suspicious > 0:
                    print(f"Найдена угроза для IP {ip}: вредоносных={malicious}, подозрительных={suspicious}")
                    self.threats.append({
                        'type': 'malicious_ip',
                        'data': result
                    })
                    # Сразу блокируем опасный IP
                    self.blocked_ips.append(ip)
                
                return result
            else:
                print(f"Ошибка API VirusTotal для {ip}: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Ошибка при проверке IP {ip}: {str(e)}")
            return None
    
    def find_vulnerabilities(self, software):
        """
        Поиск уязвимостей через Vulners
        
        Args:
            software: название ПО (например, "apache", "nginx")
        """
        try:
            # Формируем запрос для поиска уязвимостей с высоким CVSS
            payload = {
                "query": f"{software} AND cvss.score:[7.0 TO 10.0]",
                "size": 10,
                "fields": ["id", "title", "description", "cvss.score", "published"]
            }
            
            # Добавляем API ключ в заголовки
            headers = {
                "Content-Type": "application/json",
                "X-Api-Key": self.vulners_key
            }
            
            # Добавлен параметр verify=False для отключения проверки SSL
            response = requests.post(self.vulners_url, json=payload, headers=headers, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                # Проверяем структуру ответа
                if 'data' in data and 'search' in data['data']:
                    for item in data['data']['search']:
                        source = item.get('_source', {})
                        cvss = source.get('cvss', {})
                        if isinstance(cvss, dict):
                            cvss_score = cvss.get('score', 0)
                        else:
                            cvss_score = 0
                        
                        vuln = {
                            'id': item.get('_id', 'N/A'),
                            'title': source.get('title', 'Без названия'),
                            'cvss': cvss_score,
                            'published': source.get('published', 'Неизвестно'),
                            'description': source.get('description', '')[:150] + '...'
                        }
                        
                        vulnerabilities.append(vuln)
                        self.threats.append({
                            'type': 'vulnerability',
                            'data': vuln
                        })
                    
                    print(f"Найдено {len(vulnerabilities)} уязвимостей для {software}")
                    return vulnerabilities
                else:
                    print("Нет данных в ответе Vulners")
                    return []
            else:
                print(f"Ошибка Vulners API: {response.status_code}")
                print(f"Ответ: {response.text[:200]}")
                return []
                
        except Exception as e:
            print(f"Ошибка при поиске уязвимостей: {str(e)}")
            return []
    
    def analyze_logs(self, log_file):
        """
        Анализ логов Suricata
        
        Args:
            log_file: путь к файлу с логами
        """
        print(f"\nАнализ логов из файла {log_file}")
        
        try:
            if log_file.endswith('.json'):
                df = pd.read_json(log_file)
            else:
                print("Неподдерживаемый формат файла")
                return pd.DataFrame()
            
            print(f"Загружено {len(df)} записей")
            
            # Анализируем ошибки доступа
            if 'status' in df.columns:
                # Считаем ошибки 403 (доступ запрещен) по IP
                errors = df[df['status'] == 403]
                error_counts = errors.groupby('src_ip').size()
                
                for ip, count in error_counts.items():
                    if count > 2:  # больше 2 ошибок - подозрительно
                        print(f"Подозрительная активность от {ip}: {count} ошибок 403")
                        self.threats.append({
                            'type': 'suspicious_activity',
                            'data': {'ip': ip, 'error_count': count}
                        })
            
            return df
            
        except Exception as e:
            print(f"Ошибка при анализе логов: {str(e)}")
            return pd.DataFrame()
    
    def respond_to_threats(self):
        """
        Имитация реагирования на угрозы
        """
        print("\n" + "="*50)
        print("РЕАГИРОВАНИЕ НА УГРОЗЫ")
        print("="*50)
        
        if not self.threats:
            print("Угроз не обнаружено")
            return
        
        print(f"Обнаружено {len(self.threats)} угроз")
        
        for threat in self.threats:
            if threat['type'] == 'malicious_ip':
                ip = threat['data']['ip']
                print(f"БЛОКИРОВКА: IP {ip} добавлен в черный список (вредоносных: {threat['data']['malicious']})")
            
            elif threat['type'] == 'vulnerability':
                vuln = threat['data']
                print(f"УВЕДОМЛЕНИЕ: Найдена уязвимость {vuln['id']} с CVSS {vuln['cvss']}")
            
            elif threat['type'] == 'suspicious_activity':
                data = threat['data']
                print(f"ВНИМАНИЕ: IP {data['ip']} проявляет подозрительную активность")
    
    def generate_report(self, output_file="threat_report.json"):
        """
        Сохранение отчета в JSON
        
        Args:
            output_file: имя файла для отчета
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_threats': len(self.threats),
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips': self.blocked_ips,
            'threats': self.threats
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\nОтчет сохранен в {output_file}")
        return report
    
    def create_chart(self, output_file="threat_analysis.png"):
        """
        Создание графика
        
        Args:
            output_file: имя файла для графика
        """
        plt.figure(figsize=(10, 6))
        
        # Считаем типы угроз
        threat_types = {}
        for threat in self.threats:
            t_type = threat['type']
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        if threat_types:
            # Строим столбчатую диаграмму
            types = list(threat_types.keys())
            counts = list(threat_types.values())
            
            # Заменяем названия для красоты
            labels = {
                'malicious_ip': 'Вредоносные IP',
                'vulnerability': 'Уязвимости',
                'suspicious_activity': 'Подозрительная активность'
            }
            bar_labels = [labels.get(t, t) for t in types]
            
            plt.bar(bar_labels, counts, color=['red', 'orange', 'yellow'])
            plt.title('Распределение угроз по типам')
            plt.xlabel('Тип угрозы')
            plt.ylabel('Количество')
            
            # Добавляем подписи значений
            for i, v in enumerate(counts):
                plt.text(i, v + 0.1, str(v), ha='center')
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300)
            print(f"График сохранен в {output_file}")
            plt.show()
        else:
            print("Нет данных для построения графика")

def main():
    print("="*60)
    print("     АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ УГРОЗ")
    print("="*60)
    
    # Ключи
    VT_KEY = "1dbd26dd204bb55f48f40e3fa60c8d2c5e7c00b42c283186f704ad5d4a0df8d0"
    VULNERS_KEY = "14QWOUM41FDMIS3PESU9CXYB5KDML5Q7TXC5KFED8P1MGFF9DHOG1GB86STRXBK6"
    
    # Создаем экземпляр монитора
    monitor = ThreatMonitor(VT_KEY, VULNERS_KEY)
    
    # ШАГ 1: Сбор данных из разных источников
    
    print("\n" + "="*50)
    print("ШАГ 1: Сбор данных")
    print("="*50)
    
    # Источник 1: Логи Suricata
    if os.path.exists('logs/suricata.json'):
        logs_df = monitor.analyze_logs('logs/suricata.json')
    else:
        print("Файл логов не найден. Сначала запусти create_logs.py")
        logs_df = pd.DataFrame()
    
    # Источник 2: API VirusTotal (проверяем подозрительные IP)
    print("\nПроверка IP через VirusTotal API...")
    suspicious_ips = ['185.130.5.133', '45.155.205.233', '91.240.118.77']
    for ip in suspicious_ips:
        monitor.check_ip_virustotal(ip)
    
    # Источник 3: API Vulners (поиск уязвимостей)
    print("\nПоиск уязвимостей через Vulners API...")
    monitor.find_vulnerabilities("apache")
    monitor.find_vulnerabilities("nginx")
    
    # ШАГ 2: Анализ уже сделали внутри функций
    
    # ШАГ 3: Реагирование на угрозы
    monitor.respond_to_threats()
    
    # ШАГ 4: Отчет и визуализация
    print("\n" + "="*50)
    print("ШАГ 4: Формирование отчета и графика")
    print("="*50)
    
    monitor.generate_report('threat_report.json')
    monitor.create_chart('threat_analysis.png')
    
    print("\n" + "="*50)
    print("РАБОТА ЗАВЕРШЕНА")
    print("="*50)
    print(f"Всего угроз: {len(monitor.threats)}")
    print(f"Заблокировано IP: {len(monitor.blocked_ips)}")
    print("Созданы файлы:")
    print("  - threat_report.json (отчет)")
    print("  - threat_analysis.png (график)")

if __name__ == '__main__':
    main()