#
# Copyright (C) 2020 GrammaTech, Inc.
#
# This code is licensed under the MIT license. See the LICENSE file in
# the project root for license terms.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
#
from setuptools import setup, find_packages
import unittest


def gtirb_capstone_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover("tests", pattern="test_*.py")
    return test_suite


if __name__ == "__main__":
    setup(
        name="gtirb-capstone",
        version="0.1.0",
        author="blevine",
        author_email="blevine@grammatech.com",
        description="Utilities for rewriting GTIRB with capstone and keystone",
        package_data={"gtirb_capstone": ["gtirb_capstone/*.py"]},
        packages=find_packages(),
        test_suite="setup.gtirb_capstone_test_suite",
        install_requires=["gtirb", "capstone", "keystone-engine"],
        classifiers=["Programming Language :: Python :: 3"],
        entry_points={
            "console_scripts": ["captsone = capstone.__main__:main"]
        },
    )
