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
import imp
import setuptools


__version__ = imp.load_source(
    "pkginfo.version", "gtirb_capstone/version.py"
).__version__

if __name__ == "__main__":
    with open("README.md", "r") as fh:
        long_description = fh.read()

    setuptools.setup(
        name="gtirb-capstone",
        version=__version__,
        author="Grammatech",
        author_email="gtirb@grammatech.com",
        description="Utilities for rewriting GTIRB with capstone and keystone",
        packages=setuptools.find_packages(),
        install_requires=[
            "capstone",
            "dataclasses",
            "gtirb",
            "keystone-engine",
        ],
        classifiers=["Programming Language :: Python :: 3"],
        extras_require={
            "test": [
                "flake8",
                "isort",
                "pytest",
                "pytest-cov",
                "tox",
                "tox-wheel",
                "pre-commit",
            ]
        },
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/grammatech/gtirb-functions",
        license="MIT",
    )
