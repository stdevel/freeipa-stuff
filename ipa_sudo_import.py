#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A script for importing sudo command (group) definitions.
"""
# 2018 by Christian Stankowic
# <info at cstan dot io>
# https://github.com/stdevel
#

import argparse
import logging
import subprocess
import json

__version__ = "0.3.0"
"""
str: Tool version
"""
LOGGER = logging.getLogger('ipa_sudo_import.py')
"""
logging: Logger instance
"""


def run_cmd(command=""):
    """
    This function executes a command
    """
    if OPTIONS.dry_run:
        # print what would be done
        LOGGER.info("I'd like to execute the following command: %s", command)
    else:
        # run the command, it's tricky!
        output = subprocess.Popen(
            "LANG=C {0}".format(command), shell=True, stdout=subprocess.PIPE
        ).stdout.read()
        LOGGER.debug("Output of '%s' => '%s'", command, output)


def get_json(filename):
    """
    Reads a JSON file and returns the whole content as one-liner.
    :param filename: the JSON filename
    :type filename: str
    """
    try:
        with open(filename, "r") as json_file:
            json_data = json_file.read().replace("\n", "")
        return json_data
    except IOError as err:
        LOGGER.error("Unable to read file '%s': '%s'", filename, err)


def import_definitions(catalog_file):
    """
    This function imports all sudo definitions by iterating through all the
    definitions and running adequate ipa commands
    """
    # load JSON file
    catalog_json = json.loads(
        get_json(catalog_file)
    )
    # retrieve commands
    commands = {}
    catalog_version = catalog_json["metadata"]["version"]
    command_groups = catalog_json["groups"]
    all_commands = catalog_json['commands']
    # set-up commands per group
    for group in command_groups:
        commands[group] = all_commands[group]

    # print definition version:
    if OPTIONS.info_only:
        total = [len(v) for v in commands.values()]
        counter = 0
        for i in total:
            counter += i
        LOGGER.info(
            "This definition has version %s and consists of %i command "
            "groups and %i commands.",
            catalog_version, len(command_groups), counter
        )
        exit(0)

    # print definitions
    if OPTIONS.list_only:
        for group in command_groups:
            LOGGER.info(
                "Group '%s' (%s) has the following commands:",
                group, command_groups[group]
            )
            LOGGER.info('  %s', ', '.join(commands[group]))
        exit(0)

    # simulate/import definitions
    for group in command_groups:
        run_cmd("ipa sudocmdgroup-add {0} --desc='{1}'".format(
            group, command_groups[group]))
        for commandline in commands[group]:
            run_cmd(
                "ipa sudocmd-add '{0}' && ipa sudocmdgroup-add-member {1} "
                "--sudocmds='{0}'".format(commandline, group)
            )


def parse_options():
    """
    This function defines and parses options
    """
    description = "ipa_sudo_import is used to import a basic set of sudo commands and command " \
                  "groups into an existing FreeIPA installation. "
    epilog = '''Check-out the website for more details:
    http://github.com/stdevel/freeipa-stuff'''
    parser = argparse.ArgumentParser(
        epilog=epilog, description=description, version=__version__
    )

    # define option groups
    gen_opts = parser.add_argument_group("Generic options")
    cat_opts = parser.add_argument_group("Catalog options")

    # GENERIC OPTIONS
    # -d / --debug
    gen_opts.add_argument(
        "-d", "--debug", dest="debug", default=False, action="store_true",
        help="enable debugging outputs (default: no)"
    )
    # -n / --dry-run
    gen_opts.add_argument(
        "-n", "--dry-run", dest="dry_run", default=False, action="store_true",
        help="only simulates what the script would do (default: no)"
    )
    # -i / --info-only
    gen_opts.add_argument(
        "-i", "--info-only", dest="info_only",
        default=False, action="store_true",
        help="only print definition version and quits (default: no)"
    )
    # -l / --list-only
    gen_opts.add_argument(
        "-l", "--list-only", dest="list_only",
        default=False, action="store_true",
        help="only prints definitions and quits (default: no)"
    )

    cat_opts.add_argument(
        "catalog_file", metavar="FILE", nargs=1, help="Catalog file"
    )

    # parse and return options and arguments
    parser_arguments = parser.parse_args()
    return parser_arguments


if __name__ == "__main__":
    OPTIONS = parse_options()
    # set logger level
    if OPTIONS.debug:
        logging.basicConfig(level=logging.DEBUG)
        LOGGER.setLevel(logging.DEBUG)
    else:
        logging.basicConfig()
        LOGGER.setLevel(logging.INFO)

    LOGGER.debug("Options: %s", OPTIONS)

    # import definitions
    import_definitions(OPTIONS.catalog_file[0])
