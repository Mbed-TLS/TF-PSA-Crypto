# components-release.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Release preparation
################################################################

next_product_version () {
    perl -n - CMakeLists.txt <<'EOF'
        if (/^ *set *\( *[0-9A-Z_a-z]+_VERSION +([0-9]+)\.([0-9]+)[.\)]/) {
            printf "%d.%d.0\n", $1, $2 + 1;
            $found = 1;
            exit 0;
        }
        END {
            if (!$found) {
                print STDERR "Product version not found in CMakeLists.txt\n";
                exit 1;
            }
        }
EOF
}

git_clone_recursively () {
    git clone --no-checkout "$1" .
    git -c advice.detachedHead=false checkout "$(git -C "$1" rev-parse HEAD)"
    git submodule init
    # Make the framework a clone of the original framework. This gives us
    # access to local commits that may not have been pushed to the
    # submodule's URL.
    git clone --no-checkout "$1/framework" framework
    git -c advice.detachedHead=false -C framework checkout "$(git -C "$1/framework" rev-parse HEAD)"
    if ! git diff --quiet framework; then
        git commit -m 'Update framework submodule' framework
    fi
}

component_test_prepare_release () {
    msg "Prepare release: Set up testing environment"

    # Release preparation needs a clean worktree and can make commits.
    # To avoid messing up the source directory and the current branch,
    # do all this work in a separate git clone.
    # We could use a git worktree, but that would leave traces behind,
    # and having submodules that are worktrees is not well supported.
    # So we use clones.
    source_dir=$PWD
    preparation_dir=$OUT_OF_SOURCE_DIR/prep
    artifacts_dir=$OUT_OF_SOURCE_DIR/artifacts
    mkdir "$preparation_dir" "$artifacts_dir"

    new_version=$(next_product_version)
    echo "Simulating the next minor release: $new_version"

    # Set up a minimal environment with just a few tools that should
    # be enough to build the library from a release archive.
    mkdir "$minimal_bin_dir"
    # Remove the quiet make/cmake wrappers from the path. They wouldn't
    # work in the minimal environment.
    PATH=${PATH#*/quiet:}
    for x in ar as cc cmake ld ln make; do
        ln -s "$(command -v $x)" "$minimal_bin_dir/$x"
    done

    msg "Prepare release: Set up clone"
    # We'll use the files as they are committed into Git, except that
    # each submodule is considered separately. On the CI, this shouldn't
    # be a problem, but locally, the developer running this script may
    # have changed files. Complain loudly but go on anyway.
    # Don't complain about changes to all.sh components since they don't
    # matter. This makes it possible to quickly test changes on the
    # current script. (On the other hand, you do need to commit any changes
    # to prepare_release.py.)
    # Treat each submodule independently, because we'll clone whatever commit
    # is checked out in the original tree, not the submodule commit referenced
    # from the parent tree.
    if ! git diff --quiet --ignore-submodules HEAD ':!tests/scripts/components-*.sh'; then
        echo
        echo '**** THE TEST MAY NOT BE CONCLUSIVE! ****'
        echo 'There are changed files in the main worktree.'
        echo 'The test will run on what is commited into Git:'
        echo "  $(git rev-parse HEAD)"
        echo '*****************************************'
    fi
    if ! git -C framework diff --quiet HEAD; then
        echo
        echo '**** THE TEST MAY NOT BE CONCLUSIVE! ****'
        echo 'There are changed files in the framework.'
        echo 'The test will run on what is commited into Git:'
        echo "  $(git -C framework rev-parse HEAD)"
        echo '*****************************************'
    fi
    cd "$preparation_dir"
    git_clone_recursively "$source_dir"

    msg "Prepare release: Prepare release"
    echo "Prepare $new_version release in $PWD"
    framework/scripts/prepare_release.py --artifact-directory "$artifacts_dir" -r "$new_version"
    preparation_sha=$(git rev-parse HEAD)
    cd "$source_dir"
    # Make the release candidate sha available in the original git worktree
    # until the next git gc.
    git fetch --no-write-fetch-head "$preparation_dir" "$preparation_sha"
    echo ">>>> Release candidate sha: $preparation_sha <<<<"
}
