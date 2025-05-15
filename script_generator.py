import json
import os
from jinja2 import Environment, FileSystemLoader

def load_param_schema():
    with open('param_schemas.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def ask_params(params):
    answers = {}
    for p in params:
        prompt = f"{p['question']} [{p.get('default', '')}]: "
        ans = input(prompt).strip()
        if not ans:
            ans = p.get('default', '')
        answers[p['name']] = ans
    return answers

def main():
    env = Environment(loader=FileSystemLoader('templates'))
    schemas = load_param_schema()

    templates_map = {
        "1": "base_config.j2"
    }

    print("Выберите шаблон для генерации конфигурации:")
    print("1 - Базовая настройка MikroTik")
    choice = input("Введите номер шаблона: ").strip()

    if choice not in templates_map:
        print("Некорректный выбор.")
        return

    template = env.get_template(templates_map[choice])
    schema = schemas["base_config"]
    params = ask_params(schema["parameters"])

    result = template.render(params)
    filename = f"mikrotik_config_{choice}.rsc"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(result)

    print(f"Файл конфигурации сохранён: {filename}")

if __name__ == '__main__':
    main()
