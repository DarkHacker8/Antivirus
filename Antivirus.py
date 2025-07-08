import re
import os
import platform
from pathlib import Path

def virustotal(file_path, search_patterns):
    unique_lines = set()
    try:
        # Проверка на симлинк и права доступа
        real_path = Path(os.path.realpath(file_path))
        if real_path.is_symlink():
            print(f"Предупреждение: {file_path} — символическая ссылка. Анализ может быть неточным.")
        
        if not os.access(real_path, os.R_OK):
            print(f"Ошибка: Нет прав на чтение файла {real_path}.")
            return

        # Потоковое чтение больших файлов
        with open(real_path, 'r', encoding='utf-8', errors='replace') as f:
            current_comment = False
            for line in f:
                stripped_line = line.strip()
                
                # Обработка многострочных комментариев (/* ... */)
                if '/*' in stripped_line:
                    current_comment = True
                if current_comment:
                    if '*/' in stripped_line:
                        current_comment = False
                    continue

                # Пропуск однострочных комментариев
                if stripped_line.startswith(('#', '//', '<!--')):
                    continue

                # Проверка паттернов с приоритетом
                for pattern, (level, desc) in search_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        if stripped_line not in unique_lines:
                            unique_lines.add(stripped_line)
                            print(f"[{level}] {desc}: {stripped_line[:50]}...")

    except (FileNotFoundError, PermissionError) as e:
        print(f"Ошибка: {e}")
    except UnicodeDecodeError:
        print(f"Ошибка декодирования: Некорректная кодировка файла.")
    except MemoryError:
        print("Ошибка: Файл слишком большой.")
    except Exception as e:
        print(f"Неизвестная ошибка: {e}")

def antivirus():
    # Кроссплатформенная очистка экрана
    os.system('cls' if platform.system() == 'Windows' else 'clear')
    
    print("""
 █████╗ ███╗   ██╗████████╗██╗██╗   ██╗██╗██████╗ ██╗   ██╗███████╗
██╔══██╗████╗  ██║╚══██╔══╝██║██║   ██║██║██╔══██╗██║   ██║██╔════╝
███████║██╔██╗ ██║   ██║   ██║██║   ██║██║██████╔╝██║   ██║███████╗
██╔══██║██║╚██╗██║   ██║   ██║╚██╗ ██╔╝██║██╔═══╝ ██║   ██║╚════██║
██║  ██║██║ ╚████║   ██║   ██║ ╚████╔╝ ██║██║     ╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝
""")
    file = input("Путь к файлу > ")

    # Паттерны с уровнями опасности и описанием
    danger_patterns = {
        r'\brm\s+-[rf]\b': ('CRITICAL', 'Удаление файлов с принудительными флагами'),
        r'\bchmod\s+777\b': ('HIGH', 'Изменение прав доступа на все'),
        r'\b(wget|curl)\s+-O\s+http': ('MEDIUM', 'Загрузка файлов из ненадёжных источников'),
        r'\bsudo\s+.*?-[^ ]*[rf]\b': ('CRITICAL', 'Опасное использование sudo'),
        r'\beval\s*\(.*\)': ('CRITICAL', 'Исполнение произвольного кода'),
        r'\bexec\s*\(.*\)': ('CRITICAL', 'Запуск внешних процессов'),
        r'\brequests\.(get|post)\s*\(.*http': ('MEDIUM', 'Сетевая активность'),
        r'\b(os|subprocess)\.(system|Popen)\s*\(.*shell=True': ('HIGH', 'Исполнение команд через shell'),
        r'\b(password|token)\s*=\s*["\']\w+["\']': ('HIGH', 'Утечка секретных данных'),
    }

    virustotal(file, danger_patterns)

if __name__ == "__main__":
    antivirus()