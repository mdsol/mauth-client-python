# Load the version from the project metatdata
try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    # needed for Python < 3.8
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)
