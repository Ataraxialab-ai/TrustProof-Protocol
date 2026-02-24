import argparse


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="trustproof",
        description="TrustProof CLI placeholder.",
    )


def main() -> int:
    parser = build_parser()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
