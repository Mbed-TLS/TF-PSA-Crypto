#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""
Test Mbed TLS with a subset of algorithms.

This script can be divided into several steps:

First, include/mbedtls/mbedtls_config.h or a different config file passed
in the arguments is parsed to extract any configuration options (using config.py).

Then, test domains (groups of jobs, tests) are built based on predefined data
collected in the DomainData class. Here, each domain has five major traits:
- domain name, can be used to run only specific tests via command-line;
- configuration building method, described in detail below;
- list of symbols passed to the configuration building method;
- commands to be run on each job (only build, build and test, or any other custom);
- optional list of symbols to be excluded from testing.

The configuration building method can be one of the three following:

- ComplementaryDomain - build a job for each passed symbol by disabling a single
  symbol and its reverse dependencies (defined in REVERSE_DEPENDENCIES);

- ExclusiveDomain - build a job where, for each passed symbol, only this particular
  one is defined and other symbols from the list are unset. For each job look for
  any non-standard symbols to set/unset in EXCLUSIVE_GROUPS. These are usually not
  direct dependencies, but rather non-trivial results of other configs missing. Then
  look for any unset symbols and handle their reverse dependencies.
  Examples of EXCLUSIVE_GROUPS usage:
  - PSA_WANT_ALG_SHA_512 job turns off all hashes except SHA512. MBEDTLS_SSL_COOKIE_C
    requires either SHA256 or SHA384 to work, so it also has to be disabled.
    This is not a dependency on SHA512, but a result of an exclusive domain
    config building method. Relevant field:
    'PSA_WANT_ALG_SHA_512': ['-MBEDTLS_SSL_COOKIE_C'],

- DualDomain - combination of the two above - both complementary and exclusive domain
  job generation code will be run. Currently only used for hashes.

Lastly, the collected jobs are executed and (optionally) tested, with
error reporting and coloring as configured in options. Each test starts with
a full config without a couple of slowing down or unnecessary options
(see set_reference_config), then the specific job config is derived.
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import traceback

# Add the Mbed TLS Python library directory to the module search path
import scripts_path # pylint: disable=unused-import
import config
from mbedtls_framework import c_build_helper
from mbedtls_framework import crypto_knowledge
from mbedtls_framework import psa_information


class Colors: # pylint: disable=too-few-public-methods
    """Minimalistic support for colored output.
Each field of an object of this class is either None if colored output
is not possible or not desired, or a pair of strings (start, stop) such
that outputting start switches the text color to the desired color and
stop switches the text color back to the default."""
    red = None
    green = None
    cyan = None
    bold_red = None
    bold_green = None
    def __init__(self, options=None):
        """Initialize color profile according to passed options."""
        if not options or options.color in ['no', 'never']:
            want_color = False
        elif options.color in ['yes', 'always']:
            want_color = True
        else:
            want_color = sys.stderr.isatty()
        if want_color:
            # Assume ANSI compatible terminal
            normal = '\033[0m'
            self.red = ('\033[31m', normal)
            self.green = ('\033[32m', normal)
            self.cyan = ('\033[36m', normal)
            self.bold_red = ('\033[1;31m', normal)
            self.bold_green = ('\033[1;32m', normal)
NO_COLORS = Colors(None)

def log_line(text, prefix='depends.py:', suffix='', color=None):
    """Print a status message."""
    if color is not None:
        prefix = color[0] + prefix
        suffix = suffix + color[1]
    sys.stderr.write(prefix + ' ' + text + suffix + '\n')
    sys.stderr.flush()

def log_command(cmd):
    """Print a trace of the specified command.
cmd is a list of strings: a command name and its arguments."""
    log_line(' '.join(cmd), prefix='+')

class Job:
    """A job builds the library in a specific configuration and runs some tests."""
    def __init__(self, name, config_settings, commands):
        """Build a job object.
The job uses the configuration described by config_settings. This is a
dictionary where the keys are preprocessor symbols and the values are
booleans or strings. A boolean indicates whether or not to #define the
symbol. With a string, the symbol is #define'd to that value.
After setting the configuration, the job runs the programs specified by
commands. This is a list of lists of strings; each list of string is a
command name and its arguments and is passed to subprocess.call with
shell=False."""
        self.name = name
        self.config_settings = config_settings
        self.commands = commands

    def announce(self, colors, what):
        '''Announce the start or completion of a job.
If what is None, announce the start of the job.
If what is True, announce that the job has passed.
If what is False, announce that the job has failed.'''
        if what is True:
            log_line(self.name + ' PASSED', color=colors.green)
        elif what is False:
            log_line(self.name + ' FAILED', color=colors.red)
        else:
            log_line('starting ' + self.name, color=colors.cyan)

    def configure(self, options, conf, colors):
        """Generate the job's configuration through CMake."""
        settings = {'MBEDTLS_TEST_HOOKS': False}
        settings.update(self.config_settings)
        enabled = []
        disabled = []
        for key, value in sorted(settings.items()):
            if key not in conf.settings:
                log_line('Symbol {} was not found in {}'.format(key, conf.filename()),
                         color=colors.red)
                return False
            if value is False:
                disabled.append(key)
            elif value is True:
                enabled.append(key)
            else:
                enabled.append(key + '=' + value)
        command = [
            'cmake', '-S', '.', '-B', options.build_dir,
        ] + shlex.split(options.cmake_config_options) + [
            '-DENABLE_TESTING=ON',
            '-DTF_PSA_CRYPTO_CONFIG_FILE=',
            '-DTF_PSA_CRYPTO_CONFIG_BASE_FILE=' + os.path.abspath(options.config),
            '-DTF_PSA_CRYPTO_CONFIG_NAME=full',
            '-DTF_PSA_CRYPTO_CONFIG_SET=' + ';'.join(enabled),
            '-DTF_PSA_CRYPTO_CONFIG_UNSET=' + ';'.join(disabled),
        ]
        command_log = ''
        for arg in command:
            if arg.startswith(('-DTF_PSA_CRYPTO_CONFIG_SET=',
                               '-DTF_PSA_CRYPTO_CONFIG_UNSET=')):
                name, value = arg.split('=', 1)
                command_log += '\n    ' + name + '='
                if value:
                    command_log += '\n        ' + ';\n        '.join(value.split(';'))
            else:
                command_log += (' ' if command_log else '') + shlex.quote(arg)
        log_line(command_log, prefix='+')
        ret = subprocess.call(command)
        if ret != 0:
            log_line('*** [{}] Error {}'.format(' '.join(command), ret))
            return False
        return True

    def _consistency_check(self, config_file):
        '''Check if the testable option is consistent with the goal.

        The purpose of this function to ensure that every option is set or unset according to
        the settings.
        '''
        log_command(['consistency check'])
        c_name = None
        exe_name = None
        header = ('#define TF_PSA_CRYPTO_CONFIG_FILE ' + json.dumps(config_file) + '\n'
                  '#include "tf-psa-crypto/build_info.h"\n')

        # Generate a C error directive for each setting to test if it is active
        for option, value in sorted(self.config_settings.items()):
            header += '#if '
            if value:
                header += '!'
            header += f'defined({option})\n'
            header += f'#error "{option}"\n'
            header += '#endif\n'

        try:
            # Generate a C file, build and run it
            c_file, c_name, exe_name = c_build_helper.create_c_file(self.name)
            c_build_helper.generate_c_file(c_file, 'depends.py', header, lambda x: '')
            c_file.close()
            c_build_helper.compile_c_file(c_name, exe_name)
            return True

        except c_build_helper.CompileError as e:
            # Read the command line output to find out which setting has been failed
            failed = {m.group(1) for m in re.finditer('.*#error "(.*)"', e.message) if m}
            log_line('Inconsistent config option(s):')
            for option in sorted(failed):
                log_line('  ' + option)
            return False

        finally:
            c_build_helper.remove_file_if_exists(c_name)
            c_build_helper.remove_file_if_exists(exe_name)

    def test(self, options):
        '''Run the job's build and test commands.
Return True if all commands succeed. Stop this job on any failure: later
commands may depend on the configuration or build produced by earlier ones.'''
        if not self._consistency_check(os.path.abspath(
                os.path.join(options.build_dir, 'include', 'psa', 'crypto_config.h'))):
            return False
        for command in self.commands:
            log_command(command)
            env = os.environ.copy()
            if 'MBEDTLS_TEST_CONFIGURATION' in env:
                env['MBEDTLS_TEST_CONFIGURATION'] += '-' + self.name
            ret = subprocess.call(command, env=env)
            if ret != 0:
                log_line('*** [{}] Error {}'.format(' '.join(command), ret))
                return False
        return True

# If the configuration option A requires B, make sure that
# A is in REVERSE_DEPENDENCIES[B].
# These dependencies are checked by the TF-PSA-Crypto configuration checks.
# MBEDTLS_* entries here are crypto options still present in crypto_config.h.
# This file includes a copy because it changes rarely and it would be a pain
# to extract automatically.
REVERSE_DEPENDENCIES = {
    'PSA_WANT_KEY_TYPE_AES': ['PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128',
                              'MBEDTLS_CTR_DRBG_C',
                              'MBEDTLS_NIST_KW_C'],
    'PSA_WANT_KEY_TYPE_CHACHA20': ['PSA_WANT_ALG_CHACHA20_POLY1305',
                                   'PSA_WANT_ALG_STREAM_CIPHER'],
    'PSA_WANT_ALG_CCM': ['PSA_WANT_ALG_CCM_STAR_NO_TAG'],
    'PSA_WANT_ALG_CMAC': ['PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128'],

    'PSA_WANT_ECC_SECP_R1_256': ['PSA_WANT_ALG_JPAKE'],

    'PSA_WANT_ALG_ECDSA': ['PSA_WANT_ALG_DETERMINISTIC_ECDSA'],
    'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC': [
        'PSA_WANT_ALG_ECDSA',
        'PSA_WANT_ALG_ECDH',
        'PSA_WANT_ALG_JPAKE',
        'PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY',
        'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT',
        'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT',
        'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE',
        'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE',
        'MBEDTLS_ECP_RESTARTABLE',
        'MBEDTLS_PK_PARSE_EC_EXTENDED',
        'MBEDTLS_PK_PARSE_EC_COMPRESSED'],
    'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC': [
        'PSA_WANT_ALG_RSA_PKCS1V15_SIGN',
        'PSA_WANT_ALG_RSA_PKCS1V15_CRYPT',
        'PSA_WANT_ALG_RSA_OAEP',
        'PSA_WANT_ALG_RSA_PSS',
        'PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY',
        'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT',
        'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT',
        'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE'],

    'PSA_WANT_ALG_SHA_224': ['MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT',
                             'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY'],
    'PSA_WANT_ALG_SHA_256': ['MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT',
                             'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY',
                             'MBEDTLS_LMS_C',
                             'MBEDTLS_LMS_PRIVATE',
                             'PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS'],
    'PSA_WANT_ALG_SHA_512': ['MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT',
                             'MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY'],
    'PSA_WANT_ALG_ECB_NO_PADDING' : ['MBEDTLS_NIST_KW_C'],
}

# If an option is tested in an exclusive test, alter the following defines.
# These are not necessarily dependencies, but just minimal required changes
# if a given define is the only one enabled from an exclusive group.
EXCLUSIVE_GROUPS = {
    'PSA_WANT_ECC_MONTGOMERY_448': ['-PSA_WANT_ALG_ECDSA',
                                    '-PSA_WANT_ALG_JPAKE',],
    'PSA_WANT_ECC_MONTGOMERY_255': ['-PSA_WANT_ALG_ECDSA',
                                    '-PSA_WANT_ALG_JPAKE'],
    'PSA_WANT_KEY_TYPE_ARIA': ['-PSA_WANT_ALG_CMAC',
                               '-PSA_WANT_ALG_CCM',
                               '-PSA_WANT_ALG_GCM'],
    'PSA_WANT_KEY_TYPE_CAMELLIA': ['-PSA_WANT_ALG_CMAC'],
    'PSA_WANT_KEY_TYPE_CHACHA20': ['-PSA_WANT_ALG_CMAC',
                                   '-PSA_WANT_ALG_CCM',
                                   '-PSA_WANT_ALG_GCM',
                                   '-PSA_WANT_ALG_ECB_NO_PADDING'],
}
def handle_exclusive_groups(config_settings, symbol):
    """For every symbol tested in an exclusive group check if there are other
defines to be altered. """
    for dep in EXCLUSIVE_GROUPS.get(symbol, []):
        unset = dep.startswith('-')
        dep = dep[1:]
        config_settings[dep] = not unset

def turn_off_dependencies(config_settings, exclude=None):
    """For every option turned off config_settings, also turn off what depends on it.

    An option O is turned off if config_settings[O] is False.
    Handle the dependencies recursively.

    If 'exclude' is a symbol, ensure its dependencies are not turned off while dependencies
    of other settings are turned off.
    """

    # Determine recursively the settings that should not be turned off for the sake of 'exclude'.
    excludes = set()
    if exclude:
        revdep = set(REVERSE_DEPENDENCIES.get(exclude, []))
        while revdep:
            dep = revdep.pop()
            excludes.add(dep)
            revdep.update(set(REVERSE_DEPENDENCIES.get(dep, [])) - excludes)

    for key, value in sorted(config_settings.items()):
        if value is not False:
            continue

        # Save the processed settings to handle cross referencies.
        # Start with set of settings that we do not want to turn off.
        history = excludes.copy()
        revdep = set(REVERSE_DEPENDENCIES.get(key, [])) - excludes
        while revdep:
            dep = revdep.pop()
            history.add(dep)
            config_settings[dep] = False
            # Do not add symbols which are already processed
            revdep.update(set(REVERSE_DEPENDENCIES.get(dep, [])) - history)

class BaseDomain: # pylint: disable=too-few-public-methods, unused-argument
    """A base class for all domains."""
    def __init__(self, symbols, commands, exclude):
        """Initialize the jobs container"""
        self.jobs = []

class ExclusiveDomain(BaseDomain): # pylint: disable=too-few-public-methods
    """A domain consisting of a set of conceptually-equivalent settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol set and the others unset."""
    def __init__(self, symbols, commands, exclude=None):
        """Build a domain for the specified list of configuration symbols.
The domain contains a set of jobs that enable one of the elements
of symbols and disable the others.
Each job runs the specified commands.
If exclude is a regular expression, skip generated jobs whose description
would match this regular expression."""
        super().__init__(symbols, commands, exclude)
        base_config_settings = {}
        for symbol in symbols:
            base_config_settings[symbol] = False
        for symbol in symbols:
            description = symbol
            if exclude and re.match(exclude, description):
                continue
            config_settings = base_config_settings.copy()
            config_settings[symbol] = True
            handle_exclusive_groups(config_settings, symbol)
            turn_off_dependencies(config_settings, symbol)
            job = Job(description, config_settings, commands)
            self.jobs.append(job)

class ComplementaryDomain(BaseDomain): # pylint: disable=too-few-public-methods
    """A domain consisting of a set of loosely-related settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol unset.
If exclude is a regular expression, skip generated jobs whose description
would match this regular expression."""
    def __init__(self, symbols, commands, exclude=None):
        """Build a domain for the specified list of configuration symbols.
Each job in the domain disables one of the specified symbols.
Each job runs the specified commands."""
        super().__init__(symbols, commands, exclude)
        for symbol in symbols:
            description = '!' + symbol
            if exclude and re.match(exclude, description):
                continue
            config_settings = {symbol: False}
            turn_off_dependencies(config_settings)
            job = Job(description, config_settings, commands)
            self.jobs.append(job)

class DualDomain(ExclusiveDomain, ComplementaryDomain): # pylint: disable=too-few-public-methods
    """A domain that contains both the ExclusiveDomain and BaseDomain tests.
Both parent class __init__ calls are performed in any order and
each call adds respective jobs. The job array initialization is done once in
BaseDomain, before the parent __init__ calls."""

class DomainData:
    """A container for domains and jobs, used to structurize testing."""
    def config_symbols_matching(self, regexp):
        """List the crypto_config.h settings matching regexp."""
        return [symbol for symbol in self.all_config_symbols
                if re.match(regexp, symbol)]

    # pylint: disable=too-many-locals
    def __init__(self, options, conf):
        """Gather data about the library and establish a list of domains to test."""
        if options.build_and_test_command:
            build_and_test = [[options.build_and_test_command]]
        else:
            build_and_test = [
                ['cmake', '--build', options.build_dir, '--clean-first'],
                ['cmake', '-E', 'chdir', options.build_dir,
                 'ctest', '--output-on-failure'],
            ]
        self.all_config_symbols = set(conf.settings.keys())
        psa_info = psa_information.Information().constructors
        algs = {crypto_knowledge.Algorithm(alg): symbol
                for alg, symbol in ((alg, psa_information.psa_want_symbol(alg))
                                    for alg in psa_info.algorithms)
                if symbol in self.all_config_symbols}
        cipher_algs = {alg
                       for alg in algs
                       if alg.can_do(crypto_knowledge.AlgorithmCategory.CIPHER)}
        key_types = {crypto_knowledge.KeyType(expr): symbol
                     for key_type in psa_info.key_types
                     for expr, symbol in ((expr, psa_information.psa_want_symbol(key_type))
                                          for expr in psa_info.generate_expressions([key_type]))
                     if symbol in self.all_config_symbols}

        # Find hash modules by category.
        hash_symbols = {symbol
                        for alg, symbol in algs.items()
                        if alg.can_do(crypto_knowledge.AlgorithmCategory.HASH)}

        # Find elliptic curve enabling macros by name.
        curve_symbols = self.config_symbols_matching(r'PSA_WANT_ECC_\w+\Z')

        # Find cipher key types
        cipher_key_types = {symbol
                            for key_type, symbol in key_types.items()
                            for alg in cipher_algs
                            if key_type.can_do(alg)}

        # Get cipher modes
        cipher_chaining_symbols = {algs[cipher_alg] for cipher_alg in cipher_algs}

        self.domains = {
            # Cipher key types
            'cipher_id': ExclusiveDomain(cipher_key_types, build_and_test),

            # XTS is not yet supported via the PSA API.
            # See https://github.com/Mbed-TLS/mbedtls/issues/6384
            'cipher_chaining': ExclusiveDomain(cipher_chaining_symbols,
                                               build_and_test,
                                               exclude=r'PSA_WANT_ALG_XTS'),

            # Elliptic curves. Run the test suites.
            'curves': ExclusiveDomain(curve_symbols, build_and_test),

            # Hash algorithms. Excluding exclusive domains of MD, RIPEMD, SHA1, SHA3*,
            # SHA224 and SHA384 because the built-in entropy module is extensively used
            # across various modules, but it depends on either SHA256 or SHA512.
            # As a consequence an "exclusive" test of anything other than SHA256
            # or SHA512 with the built-in entropy module enabled is not possible.
            'hashes': DualDomain(hash_symbols, build_and_test,
                                 exclude=r'PSA_WANT_ALG_(?!SHA_(256|512))'),

            'pkalgs': ComplementaryDomain(['PSA_WANT_ALG_ECDSA',
                                           'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC',
                                           'PSA_WANT_ALG_RSA_OAEP',
                                           'PSA_WANT_ALG_RSA_PSS',
                                           'PSA_WANT_ALG_RSA_PKCS1V15_CRYPT',
                                           'PSA_WANT_ALG_RSA_PKCS1V15_SIGN',
                                           'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC'],
                                          build_and_test),
        }
        self.jobs = {}
        for domain in self.domains.values():
            for job in domain.jobs:
                self.jobs[job.name] = job

    def get_jobs(self, name):
        """Return the list of jobs identified by the given name.
A name can either be the name of a domain or the name of one specific job."""
        if name in self.domains:
            return sorted(self.domains[name].jobs, key=lambda job: job.name)
        else:
            return [self.jobs[name]]

def run(options, job, conf, colors=NO_COLORS):
    """Run the specified job (a Job instance)."""
    job.announce(colors, None)
    if not job.configure(options, conf, colors):
        job.announce(colors, False)
        return False
    success = job.test(options)
    job.announce(colors, success)
    return success

def run_tests(options, domain_data, conf):
    """Run the desired jobs.
domain_data should be a DomainData instance that describes the available
domains and jobs.
Run the jobs listed in options.tasks."""
    colors = Colors(options)
    jobs = []
    failures = []
    successes = []
    for name in options.tasks:
        jobs += domain_data.get_jobs(name)
    for job in jobs:
        success = run(options, job, conf, colors=colors)
        if not success:
            if options.keep_going:
                failures.append(job.name)
            else:
                return False
        else:
            successes.append(job.name)
    if successes:
        log_line('{} passed'.format(' '.join(successes)), color=colors.bold_green)
    if failures:
        log_line('{} FAILED'.format(' '.join(failures)), color=colors.bold_red)
        return False
    else:
        return True

def main():
    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=
            "Test Mbed TLS with a subset of algorithms.\n\n"
            "Example usage:\n"
            r"./tests/scripts/depends.py \!PSA_WANT_ALG_SHA_1 PSA_WANT_ALG_SHA_256""\n"
            "./tests/scripts/depends.py PSA_WANT_KEY_TYPE_AES hashes\n"
            "./tests/scripts/depends.py cipher_id cipher_chaining\n")
        parser.add_argument('--color', metavar='WHEN',
                            help='Colorize the output (always/auto/never)',
                            choices=['always', 'auto', 'never'], default='auto')
        parser.add_argument('-c', '--config', metavar='FILE',
                            help='Base configuration file to read',
                            default=config.TFPSACryptoConfigFile.default_path[0])
        parser.add_argument('-C', '--directory', metavar='DIR',
                            help='Change to this directory before anything else',
                            default='.')
        parser.add_argument('-k', '--keep-going',
                            help='Try all configurations even if some fail (default)',
                            action='store_true', dest='keep_going', default=True)
        parser.add_argument('-e', '--no-keep-going',
                            help='Stop as soon as a configuration fails',
                            action='store_false', dest='keep_going')
        parser.add_argument('--list-jobs',
                            help='List supported jobs and exit',
                            action='append_const', dest='list', const='jobs')
        parser.add_argument('--list-domains',
                            help='List supported domains and exit',
                            action='append_const', dest='list', const='domains')
        parser.add_argument('--cmake-config-options', metavar='OPTIONS',
                            help='CMake configure options (default: %(default)s)',
                            default='-DCMAKE_BUILD_TYPE=Release '
                                    '-DTF_PSA_CRYPTO_FATAL_WARNINGS=ON')
        parser.add_argument('--out-of-source-dir', metavar='DIR', dest='build_dir',
                            help='CMake build directory (default: %(default)s)',
                            default='out_of_source_build')
        parser.add_argument('--build-and-test-command',
                            help='Provide a custom command or script to build and test')
        parser.add_argument('tasks', metavar='TASKS', nargs='*',
                            help='The domain(s) or job(s) to test (default: all).',
                            default=True)
        options = parser.parse_args()
        os.chdir(options.directory)
        conf = config.TFPSACryptoConfig(options.config)
        domain_data = DomainData(options, conf)

        if options.tasks is True:
            options.tasks = sorted(domain_data.domains.keys())
        if options.list:
            for arg in options.list:
                for domain_name in sorted(getattr(domain_data, arg).keys()):
                    print(domain_name)
            sys.exit(0)
        else:
            sys.exit(0 if run_tests(options, domain_data, conf) else 1)
    except Exception: # pylint: disable=broad-except
        traceback.print_exc()
        sys.exit(3)

if __name__ == '__main__':
    main()
