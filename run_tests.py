import unittest
import sys
import os


def run_all_tests():
    """Discovers and runs all tests in the 'tests' directory."""
    # Ensure we are looking in the correct directory relative to this script
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tests')

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=test_dir, pattern='test_*.py')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
