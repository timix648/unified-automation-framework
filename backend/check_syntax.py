import ast
import os

for root, dirs, fnames in os.walk("app"):
    for fn in fnames:
        if fn.endswith(".py"):
            fpath = os.path.join(root, fn)
            try:
                with open(fpath, encoding="utf-8") as fh:
                    ast.parse(fh.read())
                print(f"OK: {fpath}")
            except SyntaxError as e:
                print(f"SYNTAX ERROR: {fpath} - {e}")
            except Exception as e:
                print(f"ERROR: {fpath} - {e}")
