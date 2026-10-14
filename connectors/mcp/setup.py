"""Bundle the released engine without maintaining a third source copy."""
from hashlib import sha256
import json
from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

HERE = Path(__file__).resolve().parent
PACKAGE = "api_relay_audit_mcp"


def engine_source():
    """Use the checked-out engine, or the copy generated in a source archive."""
    repository = HERE.parent.parent
    if (repository / "scripts" / "build-standalone.py").is_file():
        source = repository / "audit.py"
    else:
        source = HERE / PACKAGE / "_audit.py"
    expected = json.loads((HERE / PACKAGE / "provenance.json").read_text())["engine_sha256"]
    if not source.is_file() or sha256(source.read_bytes()).hexdigest() != expected:
        raise RuntimeError("The bundled engine must match the verified v2.5.0 audit.py SHA-256.")
    return source


class BundleEngine(build_py):
    def run(self):
        source = engine_source()
        super().run()
        destination = Path(self.build_lib) / PACKAGE / "_audit.py"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        shutil.copyfile(HERE / "config.example.json", destination.parent / "config.example.json")
        shutil.copytree(HERE / "examples", destination.parent / "examples", dirs_exist_ok=True)

    def get_outputs(self, include_bytecode=1):
        package_root = Path(self.build_lib) / PACKAGE
        generated = [package_root / "_audit.py", package_root / "config.example.json"]
        generated.extend(package_root / "examples" / source.name for source in (HERE / "examples").iterdir()
                         if source.is_file())
        return super().get_outputs(include_bytecode) + [str(path) for path in generated]


class SourceArchive(sdist):
    def make_release_tree(self, base_dir, files):
        source = engine_source()
        super().make_release_tree(base_dir, files)
        destination = Path(base_dir) / PACKAGE / "_audit.py"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


setup(cmdclass={"build_py": BundleEngine, "sdist": SourceArchive})
