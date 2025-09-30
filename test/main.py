import pytest
import sys
from pathlib import Path

if __name__ == "__main__":
    pytest_args = [str(Path(__file__).parent)]
    sys.exit(pytest.main(pytest_args))
