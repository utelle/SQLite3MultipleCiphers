import sys
import os
from pathlib import Path
from datetime import date


def render_template(content: str) -> str:
    # automatic default values
    env = dict(os.environ)

    env.setdefault("BUILD_DATE", date.today().isoformat())

    # simple {VAR} replacement
    return content.format(**env)


def main():
    if len(sys.argv) != 3:
        print("Usage: render_readme.py <template> <output>")
        sys.exit(1)

    template_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not template_path.exists():
        raise FileNotFoundError(template_path)

    content = template_path.read_text(encoding="utf-8")
    rendered = render_template(content)

    output_path.write_text(rendered, encoding="utf-8")

    print(f"Rendered {template_path} -> {output_path}")


if __name__ == "__main__":
    main()
