#!/usr/bin/python3
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
# import argparse
# import logging
# from gtirb import IR
# from .rewriting import RewritingContext


def main():
    pass
    # ap = argparse.ArgumentParser(description="Show functions in GTIRB")
    # ap.add_argument("infile")
    # ap.add_argument(
    #     "-v", "--verbose", action="store_true", help="Verbose output"
    # )

    # args = ap.parse_args()
    # logging.basicConfig(format="%(message)s")
    # logger = logging.getLogger("gtirb.functions")
    # if args.verbose:
    #     logger.setLevel(logging.DEBUG)

    # logger.info("Loading IR...")
    # ir = IR.load_protobuf(args.infile)

    # logger.info("Identifying functions...")

    # for m in ir.modules:
    #     fns = Function.build_functions(m)
    #     fns.sort(key=lambda x: x.get_name())
    #     if len(fns) > 0:
    #         print("Module: %s" % m.name)
    #         for fn in fns:
    #             print("\tFunction: %s" % fn.get_name())
    #             print(fn)

    # logger.info("Done.")


if __name__ == "__main__":
    main()
