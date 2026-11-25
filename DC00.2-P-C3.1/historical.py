"""Load the three historical packages without colliding on their supervisor names."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load_supervisor(directory, name):
    path = ROOT / directory / "supervisor" / "__init__.py"
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)


load_supervisor("DC00.2-P", "_dc002_p")
load_supervisor("DC00.2-P-C", "_dc002_c1")
load_supervisor("DC00.2-P-C2", "_dc002_c2")

from _dc002_p import validator as p
from _dc002_c1 import validation as c1
from _dc002_c2 import evidence as c2
from _dc002_c2 import harness as plan_contract
