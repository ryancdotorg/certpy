from . import *

"""Import all modules that exist in the current directory."""
# Based on https://rya.nc/so/60861023
from importlib import import_module
from pathlib import Path

for f in Path(__file__).parent.glob('*.py'):
    module_name = f.stem
    if (not module_name.startswith('_')) and (module_name not in globals()):
        module = import_module(f'.{module_name}', __package__)
        cls = getattr(module, module_name)
        cls.__module__ = __package__
        globals()[module_name] = cls

    del f, module_name
del import_module, Path
