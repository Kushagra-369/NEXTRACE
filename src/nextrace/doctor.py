import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path.cwd()

def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail else ""))
    return condition


def main():
    print("\nNEXTRACE SYSTEM DIAGNOSTICS")
    print("=" * 35)

    results = []

    results.append(check(
        "Python version",
        sys.version_info >= (3, 10),
        sys.version.split()[0]
    ))

    nmap_path = shutil.which("nmap")
    results.append(check(
        "Nmap installation",
        nmap_path is not None,
        nmap_path or "Nmap not found"
    ))

    if nmap_path:
        try:
            version = subprocess.run(
                [nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            ).stdout.splitlines()[0]
            results.append(check("Nmap version", True, version))
        except (OSError, subprocess.SubprocessError) as error:
            results.append(check("Nmap version", False, str(error)))

    for folder in ("output", "reports", "history", "tests"):
        path = ROOT / folder
        exists = path.is_dir()
        results.append(check(
            f"{folder}/ directory",
            exists,
            "available" if exists else "missing"
        ))

    package = ROOT / "src" / "nextrace"
    results.append(check(
        "NEXTRACE package",
        (package / "__init__.py").is_file()
    ))

    print("=" * 35)
    passed = sum(results)
    print(f"RESULT: {passed}/{len(results)} checks passed")

    if not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
