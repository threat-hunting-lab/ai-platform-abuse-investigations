import glob
import sys

try:
    import pyarrow.parquet as pq
except Exception:
    print("[error] pyarrow not available. Install with: pip install pyarrow")
    raise


def main(path_glob: str) -> int:
    files = sorted(glob.glob(path_glob))
    print(f"count: {len(files)}")

    for f in files:
        pf = pq.ParquetFile(f)
        schema = pf.schema_arrow  # works across old/new pyarrow

        print("\n" + f)
        for field in schema:
            print(f"  - {field.name}: {field.type}")
    return 0


if __name__ == "__main__":
    pattern = sys.argv[1] if len(sys.argv) > 1 else "datasets/output/*.parquet"
    raise SystemExit(main(pattern))
