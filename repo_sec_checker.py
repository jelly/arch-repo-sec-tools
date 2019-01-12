#!/usr/bin/env python

from argparse import ArgumentParser
from functools import partial
from glob import glob
from io import BytesIO
from multiprocessing import Pool
from multiprocessing import cpu_count
from os.path import join
from os.path import basename

from libarchive import file_reader

from tabulate import tabulate

from checksec import Elf


ARCHS = ['x86_64']
PKG_EXT = '.tar.xz'
DEFAULT_SOURCE_DIR = '/srv/ftp'
SOURCE_WHITELIST = ['core', 'extra', 'community', 'multilib']
VALID_DIRS = ['usr/bin/']


class Result:
    # TODO: use slots, measure
    def __init__(self, filename):
        self.filename = filename
        self.nopie = []
        self.norelro = []
        self.nocanary = []

    @property
    def not_secure(self):
        return self.nopie or self.norelro or self.nocanary

    @property
    def name(self):
        return basename(self.filename)

    @property
    def table(self):
        return [self.name, not self.norelro, not self.nocanary, not self.nopie]

    @property
    def results(self):
        return {'relro': self.norelro, 'canary': self.nocanary,
                'pie': self.nopie}

    def __repr__(self):
        return f"Result({self.name})"


def read_file(full, filename):
    res = Result(filename)

    with file_reader(filename) as pkg:
        for entry in pkg:
            # break if any of the files are not secure, speeding up scanning
            if not full and res.not_secure:
                break

            if not entry.isfile:
                continue
            if not any(entry.name.startswith(d) for d in VALID_DIRS):
                continue

            fp = BytesIO(b''.join(entry.get_blocks()))
            elf = Elf(fp)

            if not elf.is_elf():
                continue

            if not elf.pie():
                res.nopie.append(entry.name)
            if not elf.is_relro():
                res.norelro.append(entry.name)
            if not elf.canary():
                res.nocanary.append(entry.name)

    return res


def main(full, verbose, repo=DEFAULT_SOURCE_DIR, processes=cpu_count() * 2):
    tasks = []
    for subdir in SOURCE_WHITELIST:
        for arch in ARCHS:
            directory = join(repo, subdir, 'os', arch)
            for filename in glob(join(directory, f'*{PKG_EXT}')):
                tasks.append((filename))

    with Pool(processes=processes) as pool:
        func = partial(read_file, verbose)
        results = pool.map(func, tasks)

    table = [result.table for result in results if result.not_secure]
    print(tabulate(table, headers=["Name", "FULL RELRO", "CANARY", "PIE"]))

    if verbose:
        print()
        print('Verbose\n-------\n')
        for result in results:
            if not result.not_secure:
                continue
            for hardening, files in result.results.items():
                for f in files:
                    print(f'Missing {hardening} for {f}')


if __name__ == '__main__':
    parser = ArgumentParser(description='Repro Sec Checker')
    parser.add_argument('--repo', default=DEFAULT_SOURCE_DIR, help=f'root directory of the repo (default: {DEFAULT_SOURCE_DIR})')
    parser.add_argument('--processes', type=int, default=cpu_count() * 2, help=f'number of parallel processes (default: {cpu_count()*2})')
    parser.add_argument('--verbose', action='store_true', help='output the binary\'s which lack a hardening feature')
    parser.add_argument('--full', action='store_true', help=f'Scan every binary instead of stopping when one binary is not fully hardened')
    args = parser.parse_args()
    main(args.full, args.verbose, args.repo, args.processes)
