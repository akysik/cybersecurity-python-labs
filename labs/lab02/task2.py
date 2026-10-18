import argparse
import json
import logging
from collections import Counter
from collections.abc import Generator
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PasswordAnalysisResult:
    total_passwords: int
    weak_passwords: int
    weak_percentage: float
    average_length: float
    top_masks: list[dict]


def get_character_mask(password: str) -> str:
    """Перетворює пароль у маску символів (Upper, Lower, digit, special -> Ulds) та згортає її."""
    mask = []
    for char in password:
        if char.isupper():
            mask.append("U")
        elif char.islower():
            mask.append("L")
        elif char.isdigit():
            mask.append("d")
        else:
            mask.append("s")

    if not mask:
        return "Empty"

    collapsed = [mask[0]]
    for m in mask[1:]:
        if m != collapsed[-1]:
            collapsed.append(m)
    return "".join(collapsed)


def password_generator(file_path: Path) -> Generator[str, None, None]:
    """Порядкове читання словника генератором для економії пам'яті."""
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def analyze_wordlist(
    file_path: Path, min_length: int, top_masks_count: int
) -> PasswordAnalysisResult:
    """Аналізує словник паролів."""
    total_count = 0
    weak_count = 0
    total_length = 0
    mask_counter: Counter = Counter()

    for password in password_generator(file_path):
        total_count += 1
        p_len = len(password)
        total_length += p_len

        if p_len < min_length:
            weak_count += 1

        mask = get_character_mask(password)
        mask_counter[mask] += 1

    if total_count == 0:
        return PasswordAnalysisResult(0, 0, 0.0, 0.0, [])

    avg_len = round(total_length / total_count, 1)
    weak_pct = round((weak_count / total_count) * 100, 1)

    top_masks = []
    for mask, count in mask_counter.most_common(top_masks_count):
        pct = round((count / total_count) * 100, 1)
        top_masks.append({"mask": mask, "count": count, "percentage": pct})

    return PasswordAnalysisResult(
        total_passwords=total_count,
        weak_passwords=weak_count,
        weak_percentage=weak_pct,
        average_length=avg_len,
        top_masks=top_masks,
    )


def run_cli():
    parser = argparse.ArgumentParser(
        description="Аудитор надійності та масок словників паролів"
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        required=True,
        help="Шлях до файлу словника",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        help="Мінімальна довжина безпечного пароля (типово: 8)",
    )
    parser.add_argument(
        "--top-masks",
        type=int,
        default=5,
        help="Кількість топ-масок (типово: 5)",
    )
    parser.add_argument(
        "--output-stats",
        type=Path,
        default=None,
        help="Шлях до вихідного JSON-звіту",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s"
    )

    if not args.wordlist.exists():
        logger.error(f"Файл {args.wordlist} не знайдено.")
        return

    logger.info(
        f"Processing dictionary file {args.wordlist} using generators..."
    )
    result = analyze_wordlist(
        args.wordlist, args.min_length, args.top_masks
    )
    logger.info(f"Analyzed {result.total_passwords:,} passwords.")

    print("\n=== Password Dictionary Audit Summary ===")
    print(f"Total Passwords   : {result.total_passwords:,}")
    print(
        f"Weak Passwords (<{args.min_length}): {result.weak_passwords:,} ({result.weak_percentage}%)"
    )
    print(f"Average Length    : {result.average_length} characters")

    print(f"\n=== Top-{args.top_masks} Password Masks ===")
    for i, item in enumerate(result.top_masks, 1):
        print(
            f"{i}. Mask ({item['mask']}) : {item['count']:,} ({item['percentage']}%)"
        )

    if args.output_stats:
        args.output_stats.parent.mkdir(parents=True, exist_ok=True)
        with args.output_stats.open("w", encoding="utf-8") as f:
            json.dump(asdict(result), f, indent=4, ensure_ascii=False)
        logger.info(f"Dictionary statistics saved to {args.output_stats}")


if __name__ == "__main__":
    run_cli()