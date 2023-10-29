#!/usr/bin/env python3

"""Makefile generator for TF-PSA-Crypto.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import pathlib
import re
import sys
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Union

from mbedtls_dev import typing_util


def sjoin(*args: str) -> str:
    """Join the arguments (strings) with a single space between each."""
    return ' '.join(args)


class SourceFile:
    """A description of a file path in the source tree.
    """

    def __init__(self,
                 root: pathlib.Path,
                 inner_path: Union[pathlib.Path, str]) -> None:
        self.root = root #type: pathlib.Path
        self.inner_path = str(inner_path) #type: str

    def _sort_key(self) -> str:
        return self.inner_path

    def __lt__(self, other: 'SourceFile') -> bool:
        if self.root != other.root:
            raise TypeError("Cannot compare source files under different roots"
                            , self, other)
        return self._sort_key() < other._sort_key()

    def relative_path(self) -> str:
        """Path to the file from the root of the source tree."""
        return self.inner_path

    def source_dir(self) -> str:
        """Path to the directory containing the file, from the root of the
        source tree."""
        return os.path.dirname(self.relative_path())

    def real_path(self) -> str:
        """A path at which the file can be opened during makefile generation."""
        return str(pathlib.Path(self.root, self.inner_path))

    def make_path(self) -> str:
        """A path to the file that is valid in the makefile."""
        return '$(SOURCE_DIR)/' + self.inner_path

    def target_dir(self) -> str:
        """The target directory for build products of this source file.

        This is the path to the directory containing the source file
        inside the submodule.
        """
        return os.path.dirname(self.inner_path)

    def base(self) -> str:
        """The path to the file inside the submodule, without the extension."""
        return os.path.splitext(self.inner_path)[0]

    def target(self, extension) -> str:
        """A build target for this source file, with the specified extension."""
        return self.base() + extension


class MakefileMaker:
    """Generate a makefile for TF-PSA-Crypto.

    Typical usage:
        MakefileMaker(options, source_path).generate()
    """

    def __init__(self, options, source_path: str) -> None:
        """Initialize a makefile generator.

        options is the command line option object.

        source_path is a path to the root of the source directory,
        absolute or relative to the root of the build directory,
        and not containing characters that are special to shell or make.
        """

        # The root of the build tree.
        self.build_dir = options.dir #type: str
        # A path to the source tree, from the generator's working directory.
        self.source_path = pathlib.Path(options.source) #type: pathlib.Path
        # A path to the source tree, from the root of the build tree.
        self.source_from_build = pathlib.Path(source_path) #type: pathlib.Path

        # Set of files to remove in "make clean".
        self.clean_files = set() #type: Set[str]
        # {extension: {directories}} to remove in "make clean"
        self.clean_extensions = {} #type: Dict[str, Set[str]]
        # {target: help_text}
        self.help = {} #type: Dict[str, str]
        # Directories containing targets
        self.target_directories = set() #type: Set[str]
        # Dependencies of C files ({c_or_h_file: {h_file, ...}}). Paths are
        # relative to the source or build directory.
        self.c_dependency_cache = {} #type: Dict[str, FrozenSet[str]]
        # While generating, the output stream
        self.out = None #type: Optional[typing_util.Writable]

    #### Helpers for output generation ####

    def line(self, text: str) -> None:
        """Emit a makefile line."""
        assert self.out is not None
        self.out.write(text + '\n')

    def blank_line(self) -> None:
        """Emit a blank line."""
        self.line('')

    def comment(self, text) -> None:
        """Emit a makefile comment line containing the given text."""
        self.line('## ' + text)

    def assign(self, name: str, *value_words: str) -> None:
        """Emit a makefile line that contains an assignment.

        The assignment is to the variable called name, and its value
        is value_words joined with spaces as the separator.
        """
        nonempty_words = [word for word in value_words if word]
        self.line(' '.join([name, '='] + nonempty_words))

    def help_lines(self) -> Iterable[str]:
        """Return the lines of text to show for the 'help' target."""
        return ['{:<14} : {}'.format(name, self.help[name])
                for name in sorted(self.help.keys())]

    def add_dependencies(self, name: str, *dependencies: str) -> None:
        """Emit a dependency line for the target name."""
        # Put one dependency per physical line if the whole list is very long.
        parts = (name + ':',) + dependencies
        simple = ' '.join(parts)
        if len(simple) < 80:
            self.line(simple)
        else:
            self.line(' \\\n\t\t'.join(parts))

    def target(self, # pylint: disable=too-many-arguments
               name: str,
               dependencies: Iterable[str],
               commands: Iterable[str],
               help_text: Optional[str] = None,
               clean=True,
               phony=False,
               ) -> None:
        """Generate a makefile rule.

        * name: the target of the rule.
        * dependencies: a list of dependencies.
        * commands: a list of commands to run (the recipe).
        * help_text: documentation to show for this target in "make help".
          If this is omitted, the target is not listed in "make help".
        * clean: if true, add this target to the list of files to remove
          in "make clean". Ignored for phony targets.
        * phony: if true, declare this target as phony.
        """
        if not phony:
            self.target_directories.add(os.path.dirname(name))
        self.add_dependencies(name, *dependencies)
        for com in commands:
            self.line('\t' + com.strip('\n').replace('\n', ' \\\n\t'))
        if help_text is not None:
            self.help[name] = help_text
        if phony:
            self.line('.PHONY: ' + name)
        if not phony and clean:
            self.clean_files.add(name)

    #### Analyze source files

    def source_file(self, path: Union[pathlib.Path, str]) -> SourceFile:
        """Construct a SourceFile object for the given path."""
        return SourceFile(self.source_path, path)

    def iterate_source_files(self, *patterns: str) -> Iterator[SourceFile]:
        """List the source files matching any of the specified patterns.

        This function returns an iterator of SourceFile objects in
        an unspecified order.
        """
        for pattern in patterns:
            for path in self.source_path.glob(pattern):
                yield self.source_file(path.relative_to(self.source_path))

    def list_source_files(self, *patterns: str) -> List[SourceFile]:
        """List the source files matching any of the specified patterns.

        This function returns a sorted list of SourceFile objects.
        """
        return sorted(self.iterate_source_files(*patterns))

    #### C compilation ####

    @staticmethod
    def include_directories_for(source_dir: str) -> Iterable[str]:
        """Yield directories with header files to compile files in the specified directory."""
        yield source_dir
        yield 'include'
        if source_dir == 'core' or \
           source_dir.startswith('drivers/builtin/'):
            yield 'drivers/builtin/src'
            yield 'drivers/builtin/include'
        if source_dir.startswith('drivers/'):
            yield 'core'

    def include_options_for(self, source_dir: str) -> str:
        """Emit include path options (-I...) to compile files in the specified directory."""
        return sjoin(*(['-I include'] +
                       ['-I $(SOURCE_DIR)/' + d
                        for d in self.include_directories_for(source_dir)]))

    def collect_c_dependencies(self, c_file: str,
                               stack=frozenset()) -> FrozenSet[str]:
        """Find the build dependencies of the specified C source file.

        c_file must be an existing C file in the source tree.
        Return a set of directory paths from the root of the source tree.

        The dependencies of a C source files are the files mentioned
        in an #include directive that are present in the source tree,
        as well as dependencies of dependencies recursively.
        This function does not consider which preprocessor symbols
        might be defined: it bases its analysis solely on the textual
        presence of "#include".

        Note that dependencies in the build tree are not supported yet.

        This function uses a cache internally, so repeated calls with
        the same argument return almost instantly.

        The optional argument stack is only used for recursive calls
        to prevent infinite loops.
        """
        if c_file in self.c_dependency_cache:
            return self.c_dependency_cache[c_file]
        if c_file in stack:
            return frozenset()
        stack |= {c_file}
        include_path = list(self.include_directories_for(os.path.dirname(c_file)))
        dependencies = set()
        c_path = self.source_path.joinpath(c_file)
        with c_path.open() as stream:
            for line in stream:
                m = re.match(r' *# *include *["<](.*?)[">]', line)
                if m is None:
                    continue
                filename = m.group(1)
                for subdir in include_path:
                    if self.source_path.joinpath(subdir, filename).exists():
                        dependencies.add('/'.join([subdir, filename]))
                        break
        for dep in frozenset(dependencies):
            dependencies |= self.collect_c_dependencies(dep, stack)
        frozen = frozenset(dependencies)
        self.c_dependency_cache[c_file] = frozen
        return frozen

    def targets_for_c(self,
                      src: SourceFile,
                      deps: Iterable[str] = ()) -> None:
        """Emit targets for a .c source file."""
        dep_set = set(deps)
        for dep in self.collect_c_dependencies(src.relative_path()):
            dep_set.add(self.source_file(dep).make_path())
        for switch, extension in [
                ('-c', '$(OBJ_EXT)',),
                ('-s', '$(ASM_EXT)',),
        ]:
            self.target(src.target(extension),
                        sorted(dep_set) + [src.make_path()],
                        [sjoin('$(CC)',
                               '$(CFLAGS)',
                               self.include_options_for(src.source_dir()),
                               '-o $@',
                               switch, src.make_path())],
                        clean=False)
            self.clean_extensions.setdefault(extension, set())
            self.clean_extensions[extension].add(src.target_dir())

    #### Generate makefile sections ####

    def settings_section(self) -> None:
        """Generate assignments to customizable and internal variables.

        Some additional section-specified variables may be assigned in each
        section.
        """
        self.comment('Path settings')
        self.assign('SOURCE_DIR', str(self.source_from_build))
        self.blank_line()
        self.comment('File extensions')
        self.assign('ASM_EXT', '.s')
        self.assign('LIB_EXT', '.a')
        self.assign('OBJ_EXT', '.o')
        self.blank_line()
        self.target('default', ['lib'], [], phony=True)

    def library_section(self) -> None:
        """Generate targets to build the library."""
        c_files = self.list_source_files('core/*.c', 'drivers/builtin/src/*.c')
        object_files = []
        for c_file in c_files:
            self.targets_for_c(c_file)
            object_files.append(c_file.target('$(OBJ_EXT)'))
        self.assign('LIBTFPSACRYPTO_OBJECTS', *object_files)
        self.target('core/libtfpsacrypto$(LIB_EXT)',
                    ['$(LIBTFPSACRYPTO_OBJECTS)'],
                    ['$(AR) $(ARFLAGS) $@ $(LIBTFPSACRYPTO_OBJECTS)'])
        self.target('lib',
                    ['core/libtfpsacrypto$(LIB_EXT)'],
                    [],
                    phony=True)

    def patterns_to_clean(self) -> Iterable[str]:
        """Yield the files and wildcard patterns to remove in "make clean"."""
        yield from sorted(self.clean_files)
        for extension in sorted(self.clean_extensions.keys()):
            # It would be nice, but hard, to ensure that if the extension
            # is empty at runtime ("$(VAR)" with VAR having an empty value)
            # then we avoid running "rm dir/*".
            yield sjoin(*(os.path.join(dir, '*' + extension)
                          for dir in sorted(self.clean_extensions[extension])))

    def clean_section(self) -> None:
        """Generate a clean target."""
        self.target('clean', [],
                    ['$(RM) ' + arg for arg in self.patterns_to_clean()],
                    help_text='Remove all generated files.',
                    phony=True)

    def output_all(self) -> None:
        """Generate the makefile content."""
        self.comment('Generated by ' + ' '.join(sys.argv))
        self.comment('Do not edit this file! All modifications will be lost.')
        self.blank_line()
        self.settings_section()
        self.blank_line()
        self.library_section()
        self.blank_line()
        self.clean_section()
        self.blank_line()
        # The help target must come last because it displays accumulated help
        # text set by previous calls to self.target. Set its own help manually
        # because self.target would set it too late for it to be printed.
        self.help['help'] = 'Show this help listing the most commonly-used non-file targets.'
        self.target('help', [],
                    ['@echo "{}"'.format(line) for line in self.help_lines()],
                    phony=True)
        self.blank_line()
        self.comment('End of generated file.')

    def generate(self) -> None:
        """Generate the makefile."""
        destination = os.path.join(self.build_dir, 'Makefile')
        temp_file = destination + '.new'
        with open(temp_file, 'w', encoding='ascii') as out:
            try:
                self.out = out
                self.output_all()
            finally:
                self.out = None
        os.replace(temp_file, destination)


class BuildTreeMaker:
    """Prepare a TF-PSA-Crypto build tree.

    * Create a directory structure.
    * Create symbolic links to some files and directories from the source.
    * Create a Makefile.

    Typical usage: BuildTreeMaker(options).run()
    """

    def __init__(self, options) -> None:
        """Instantiate from command line options."""
        self.source_dir = options.source #type: str
        self.build_dir = options.dir #type: str
        # In-tree or out-of-tree build?
        self.in_tree = \
            (os.path.exists(self.build_dir) and
             os.path.samefile(self.build_dir, self.source_dir)) #type: bool
        self.makefile = MakefileMaker(options,
                                      os.curdir if self.in_tree else 'source')


    def source_from_build_root(self) -> str:
        """A path to the source root, either absolute or relative to the build root."""
        # If the build tree is a direct subdirectory of the source tree
        # (a common case), prefer a relative path. This allows moving
        # the source tree (which includes the build tree), and the build
        # tree will still work.
        if os.path.samefile(self.source_dir,
                            os.path.join(self.build_dir, os.path.pardir)):
            return os.path.pardir
        # Default to using an absolute path. This is safe except if the source
        # tree is moved.
        return os.path.abspath(self.source_dir)

    def make_link(self, target: str, link: str) -> None:
        """Create a symbolic link called link pointing to target.

        link is a path relative to the build directory.

        If the link already exists, it is not modified.
        """
        link_path = os.path.join(self.build_dir, link)
        if not os.path.lexists(link_path):
            os.symlink(target, link_path)

    def make_directory(self, sub_path: Union[pathlib.Path, str]) -> None:
        """Create a subdirectory of the build tree.

        Create parents if necessary.
        Do nothing if the specified directory already exists.
        """
        path = pathlib.Path(self.build_dir).joinpath(sub_path)
        if not path.exists():
            os.makedirs(str(path))

    def create_build_tree(self) -> None:
        """Create directories and links needed for an out-of-tree build."""
        # Source files are referenced as "source/..." rather than a
        # path to the source directory to make it easier to move the
        # source directory, and avoid any difficulty with special characters
        # such as spaces in paths.
        self.make_link(self.source_from_build_root(), 'source')
        # Create directories to override headers
        source_path = pathlib.Path(self.source_dir)
        for path in source_path.glob('include/*'):
            if path.is_dir():
                self.make_directory(path.relative_to(source_path))
        # Create directories containing targets
        for directory in self.makefile.target_directories:
            self.make_directory(directory)
        # Link to some source directories expected by scripts or programs.
        for link in [
                ['scripts'],
        ]:
            self.make_link(os.path.join(*([os.pardir] * (len(link) - 1) +
                                          ['source'] + link)),
                           os.path.join(*link))

    def run(self) -> None:
        """Create the build tree and the makefile."""
        if not os.path.exists(self.build_dir):
            os.mkdir(self.build_dir)
        self.makefile.generate()
        if not self.in_tree:
            self.create_build_tree()


def main() -> None:
    """Process the command line and prepare a build tree accordingly."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', '-d',
                        default=os.curdir,
                        help='Build directory to create (default: current directory)')
    parser.add_argument('--source', '-s',
                        default=os.curdir,
                        help='Root directory of the source tree (default: current directory)')
    options = parser.parse_args()
    builder = BuildTreeMaker(options)
    builder.run()


if __name__ == '__main__':
    main()
