# Make the top-level `agentsecgov` package resolve to the implementation under `src/agentsecgov`
# This helps pytest imports when `src` is added to PYTHONPATH via pyproject.toml
import os

# Ensure the package path includes the src/agentsecgov directory so imports like
# `from agentsecgov import main` resolve to the code under src/agentsecgov
__path__.append(os.path.join(os.path.dirname(__file__), "src", "agentsecgov"))