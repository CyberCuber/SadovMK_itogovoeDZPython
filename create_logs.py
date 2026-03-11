import os
import json
import random
from datetime import datetime, timedelta

def create_sample_logs():
    """Создание тестовых логов Suricata"""
    
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Список IP-адресов (некоторые подозрительные)
    ips = [
        '8.8.8.8',           # Google DNS
        '1.1.1.1',           # Cloudflare DNS
        '185.130.5.133',     # подозрительный
        '45.155.205.233',    # подозрительный
        '31.13.79.246',      # Facebook
        '91.240.118.77'      # подозрительный
    ]
    
    domains = [
        'google.com', 'yandex.ru', 'youtube.com', 
        'vk.com', 'malware-site.ru', 'banking-site.com'
    ]
    
    log_entries = []
    current_time = datetime.now()
    
    # Генерируем 50 записей
    for i in range(50):
        time = current_time - timedelta(
            hours=random.randint(0, 24), 
            minutes=random.randint(0, 60)
        )
        
        entry = {
            'timestamp': time.isoformat(),
            'src_ip': random.choice(ips),
            'dst_ip': random.choice(ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 8080]),
            'protocol': random.choice(['TCP', 'UDP']),
            'host': random.choice(domains),
            'status': random.choice([200, 301, 404, 403, 500])
        }
        
        # Добавляем больше ошибок для подозрительных IP
        if entry['dst_ip'] in ['185.130.5.133', '45.155.205.233', '91.240.118.77']:
            entry['status'] = 403
            entry['event_type'] = 'alert'
        else:
            entry['event_type'] = random.choice(['http', 'dns'])
        
        log_entries.append(entry)
    
    # Сохраняем в JSON
    with open('logs/suricata.json', 'w', encoding='utf-8') as f:
        json.dump(log_entries, f, indent=2, ensure_ascii=False)
    
    print(f"Создано {len(log_entries)} записей логов в папке logs/")

if __name__ == '__main__':
    create_sample_logs()
    print("Готово! Можно запускать основной скрипт.")