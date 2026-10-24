#!/usr/bin/env python3
"""Аналізатор безпеки паролів з урахуванням персональних даних.

Працює повністю локально: пароль і особисті дані нікуди не надсилаються
і не зберігаються.

Запуск:  python password_analyzer.py
"""
import getpass
import math
import re
import sys
from datetime import datetime

# --- Словники -------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "qwerty", "qwerty123", "123456", "12345678", "123456789",
    "111111", "000000", "abc123", "iloveyou", "admin", "welcome", "login",
    "letmein", "monkey", "dragon", "master", "sunshine", "princess",
    "football", "shadow", "superman", "qazwsx", "zaq12wsx", "1q2w3e4r",
    "passw0rd", "pass", "ukraine", "kharkiv", "kyiv", "lviv", "slava",
    "sonce", "parol", "pароль",
}
COMMON_WORDS = {
    "love", "hello", "secret", "master", "summer", "winter", "spring",
    "autumn", "monday", "friday", "freedom", "family", "cat", "dog",
    "gamer", "game", "user", "test", "root", "qwerty", "password",
    "ukraine", "kharkiv", "student", "university",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
                 "йцукенгшщзхї", "фівапролджє", "ячсмитьбю"]

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                      "7": "t", "@": "a", "$": "s", "!": "i"})

UA_TO_LAT = {
    "а": "a", "б": "b", "в": "v", "г": "h", "ґ": "g", "д": "d", "е": "e",
    "є": "ye", "ж": "zh", "з": "z", "и": "y", "і": "i", "ї": "yi",
    "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p",
    "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh",
    "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch", "ь": "", "ю": "yu",
    "я": "ya", "ы": "y", "э": "e", "ё": "yo", "ъ": "",
}


def translit(text: str) -> str:
    return "".join(UA_TO_LAT.get(ch, ch) for ch in text.lower())


# --- Аналіз ---------------------------------------------------------------

def name_variants(name: str) -> set:
    """Варіанти запису імені: кирилиця, транслітерація, скорочення."""
    base = name.strip().lower()
    if not base:
        return set()
    variants = {base, translit(base)}
    for v in list(variants):
        if len(v) >= 4:
            variants.add(v[:3])  # напр. "iva" з "ivan"
    return {v for v in variants if len(v) >= 3}


def date_variants(date_str: str) -> set:
    """Фрагменти дати народження, які часто потрапляють у паролі."""
    try:
        d = datetime.strptime(date_str.strip(), "%d.%m.%Y")
    except ValueError:
        return set()
    dd, mm, yyyy, yy = f"{d.day:02d}", f"{d.month:02d}", str(d.year), f"{d.year % 100:02d}"
    return {yyyy, dd + mm + yyyy, dd + mm + yy, dd + mm, mm + yyyy,
            yyyy + mm + dd, dd + mm + yyyy[2:], yyyy[2:] + mm + dd}


def find_personal(password: str, names, date_str: str):
    """Повертає список знайдених персональних даних у паролі."""
    low = password.lower()
    leet_low = low.translate(LEET)
    found = []
    for n in names:
        for v in name_variants(n):
            if v in low or v in leet_low or v[::-1] in low:
                found.append(f"ім'я/прізвище («{n}» → «{v}»)")
                break
    digits = re.sub(r"\D", "", password)
    for v in sorted(date_variants(date_str), key=len, reverse=True):
        if v in digits:
            found.append(f"фрагмент дати народження («{v}»)")
            break
    return found


def has_sequence(password: str, min_len: int = 4) -> bool:
    low = password.lower()
    for row in KEYBOARD_ROWS:
        for seq in (row, row[::-1]):
            for i in range(len(seq) - min_len + 1):
                if seq[i:i + min_len] in low:
                    return True
    # послідовності типу abcd / 1234
    run = 1
    for a, b in zip(low, low[1:]):
        run = run + 1 if ord(b) - ord(a) == 1 else 1
        if run >= min_len:
            return True
    return False


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"\d", password): size += 10
    if re.search(r"[^\w\s]|_", password): size += 33
    if re.search(r"[а-яіїєґА-ЯІЇЄҐ]", password): size += 33
    if " " in password: size += 1
    return max(size, 1)


def entropy_bits(password: str) -> float:
    return len(password) * math.log2(charset_size(password))


def analyze(password: str, names, birth_date: str) -> dict:
    score = 0.0
    issues, good, recs = [], [], []
    n = len(password)

    # Довжина (до 3.5 б.)
    if n < 8:
        issues.append(f"занадто короткий ({n} символів)")
        recs.append("Використовуйте щонайменше 12 символів, а краще 16+.")
        score += 0.5 if n >= 5 else 0
    elif n < 12:
        score += 1.5
        recs.append("Збільшіть довжину до 12–16 символів або використайте фразу-пароль.")
    elif n < 16:
        score += 2.5; good.append("достатня довжина")
    else:
        score += 3.5; good.append("відмінна довжина")

    # Різноманітність (до 2.5 б.)
    classes = sum(bool(re.search(p, password)) for p in
                  (r"[a-zа-яіїєґ]", r"[A-ZА-ЯІЇЄҐ]", r"\d", r"[^\w\s]|_"))
    score += classes * 0.625
    if classes < 3:
        issues.append(f"мала різноманітність символів ({classes} з 4 типів)")
        recs.append("Додайте великі/малі літери, цифри та спеціальні символи.")
    else:
        good.append(f"різноманітні символи ({classes} з 4 типів)")

    # Ентропія (до 2 б.)
    bits = entropy_bits(password)
    score += min(bits / 60, 1) * 2
    if bits < 40:
        issues.append(f"низька оцінка ентропії (~{bits:.0f} біт)")

    # Бонус за відсутність слабких місць (до 2.5 б.)
    bonus = 2.5

    found = find_personal(password, names, birth_date)
    if found:
        bonus -= 1.5 + 0.5 * (len(found) - 1)
        for f in found:
            issues.append(f"містить персональні дані: {f}")
        recs.append("Уникайте використання особистих даних (ім'я, дата народження, прізвисько).")

    low = password.lower()
    if low in COMMON_PASSWORDS or low.translate(LEET) in COMMON_PASSWORDS:
        bonus -= 2.5
        issues.append("входить до списку поширених паролів")
        recs.append("Не використовуйте поширені паролі: їх перебирають першими.")
    else:
        words = [w for w in COMMON_WORDS | COMMON_PASSWORDS
                 if len(w) >= 4 and (w in low or w in low.translate(LEET))]
        if words:
            bonus -= 1.0
            issues.append(f"містить словникове слово: «{words[0]}»")
            recs.append("Не використовуйте цілі слова; замініть на випадкову фразу з 4+ слів.")

    if has_sequence(password):
        bonus -= 0.75
        issues.append("містить послідовність (qwerty, 1234, abcd)")
        recs.append("Уникайте клавіатурних і числових послідовностей.")
    if re.search(r"(.)\1{2,}", password):
        bonus -= 0.5
        issues.append("містить повторення символів (aaa, 111)")
    if n and password.isdigit():
        bonus -= 0.5
        issues.append("складається лише з цифр")
    if n and re.fullmatch(r"[A-Za-zА-Яа-я]+\d{1,4}[!@#$%^&*]?", password):
        issues.append("типовий шаблон «слово + цифри»")
        recs.append("Не використовуйте шаблон «слово + цифри»: його знають зловмисники.")
        bonus -= 0.5

    score += max(bonus, 0)
    final = max(1, min(10, round(score)))
    # Пароль з персональними даними не може вважатися сильним
    if found:
        final = min(final, 4 if len(found) > 1 else 5)
    if not issues and final < 10:
        final = max(final, 8)

    if final <= 4 and not any("менеджер" in r for r in recs):
        recs.append("Скористайтеся менеджером паролів і унікальним паролем для кожного сервісу.")
    if final >= 8:
        recs.append("Увімкніть двофакторну автентифікацію (2FA) на важливих акаунтах.")

    labels = ["", "дуже слабкий", "дуже слабкий", "слабкий", "слабкий",
              "посередній", "посередній", "добрий", "сильний", "сильний", "відмінний"]
    return {"score": final, "label": labels[final], "issues": issues,
            "good": good, "recommendations": list(dict.fromkeys(recs)),
            "entropy": bits}


def crack_time(bits: float) -> str:
    """Груба оцінка часу перебору при 10^10 спроб/с (швидке офлайн-злама)."""
    secs = (2 ** bits) / 2 / 1e10
    if secs < 1: return "миттєво"
    if secs < 60: return f"{secs:.0f} с"
    if secs < 3600: return f"{secs/60:.0f} хв"
    if secs < 86400: return f"{secs/3600:.0f} год"
    if secs < 31536000: return f"{secs/86400:.0f} діб"
    years = secs / 31536000
    return f"{years:.0f} років" if years < 1e9 else "понад мільярд років"


# --- Інтерфейс ------------------------------------------------------------

def report(password, names, birth, result):
    bar = "█" * result["score"] + "░" * (10 - result["score"])
    print("\n" + "=" * 56)
    print(f" Оцінка: {result['score']}/10  [{bar}]  {result['label']}")
    print(f" Ентропія: ~{result['entropy']:.0f} біт | "
          f"оцінка часу злому: {crack_time(result['entropy'])}")
    print("=" * 56)
    if result["good"]:
        print("Сильні сторони:")
        for g in result["good"]: print(f"  + {g}")
    if result["issues"]:
        print("Проблеми:")
        for i in result["issues"]: print(f"  - {i}")
    if result["recommendations"]:
        print("Рекомендації:")
        for r in result["recommendations"]: print(f"  * {r}")
    print()


def main():
    print("=== Аналізатор безпеки паролів (локально, без передачі даних) ===")
    names = [x for x in re.split(r"[,\s]+", input("Ім'я та прізвище (через пробіл/кому): ")) if x]
    birth = input("Дата народження (ДД.ММ.РРРР): ").strip()
    if birth and not date_variants(birth):
        print("Невірний формат дати, аналіз дати пропущено.")
        birth = ""
    print("Вводьте паролі для перевірки (порожній рядок = вихід). "
          "Вводити РЕАЛЬНІ паролі не рекомендується.")
    while True:
        try:
            pw = getpass.getpass("Пароль (ввід прихований): ") if sys.stdin.isatty() else input()
        except EOFError:
            break
        if not pw:
            break
        report(pw, names, birth, analyze(pw, names, birth))


if __name__ == "__main__":
    main()
