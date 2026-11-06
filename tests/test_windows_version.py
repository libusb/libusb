#!/usr/bin/env python3
"""Test MSVC version generation with a real, isolated Git distribution."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
PS = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
OPTIONS = None
WORK = None


def run(args, env=None, cwd=None, success=True, timeout=60):
    process = subprocess.Popen([str(arg) for arg in args], env=env, cwd=cwd,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run([str(Path(os.environ['WINDIR']) / 'System32/taskkill.exe'),
                        '/PID', str(process.pid), '/T', '/F'],
                       capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        process.communicate(timeout=15)
        raise AssertionError('Command timed out: ' + str(args)) from None
    output = output.decode('utf-8', errors='replace')
    if (process.returncode == 0) != success:
        raise AssertionError(f'Exit {process.returncode}: {args}\n{output}')
    return output


def bare_environment():
    env = os.environ.copy()
    for name in ('LIBUSB_GIT', 'LIBUSB_SH', 'GIT_EXEC_PATH', 'BASH_ENV', 'ENV'):
        env.pop(name, None)
    env.update(PATH=str(PS.parent), LOCALAPPDATA=str(WORK / 'empty-profile'),
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='NUL', GIT_TERMINAL_PROMPT='0')
    return env


def tool_environment():
    env = bare_environment()
    if OPTIONS.sourcetree:
        env['LOCALAPPDATA'] = str(OPTIONS.git_root.parents[2])
    else:
        env['PATH'] = str(OPTIONS.git_root / 'cmd') + ';' + env['PATH']
    return env


def git(*args):
    return run([OPTIONS.git_root / 'cmd/git.exe', *args], env=bare_environment()).strip()


def generate(source, out, env=None, success=True):
    return run([PS, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                SOURCE / 'build-aux/gen-describe.ps1', source, out],
               env=env if env is not None else tool_environment(), success=success)


def shell_generate(source, out):
    env = bare_environment()
    env['PATH'] = ';'.join(str(OPTIONS.git_root / part) for part in ('cmd', 'usr/bin', 'bin'))
    run([OPTIONS.git_root / 'usr/bin/sh.exe',
         (SOURCE / 'build-aux/gen-describe.sh').as_posix(), source.as_posix(), out.as_posix()], env=env)


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='case + ', dir=WORK))
        self.source = self.root / 'source with spaces'
        (self.source / 'build-aux').mkdir(parents=True)
        (self.source / 'libusb').mkdir()
        for name in ('version.h', 'version_nano.h'):
            shutil.copyfile(SOURCE / 'libusb' / name, self.source / 'libusb' / name)
        shutil.copyfile(SOURCE / 'build-aux/version-describe-unknown.h',
                        self.source / 'build-aux/version-describe-unknown.h')
        self.out = self.root / 'output + spaces/version_describe.h'

    def checkout(self, no_tags=False):
        path = self.root / 'checkout + spaces'
        options = ['--no-tags'] if no_tags else []
        git('clone', '--shared', '--no-checkout', *options, str(SOURCE), str(path))
        git('-C', str(path), 'config', 'core.symlinks', 'false')
        git('-C', str(path), 'checkout', '--detach', 'HEAD')
        return path

    def test_archive_without_tools(self):
        env = bare_environment()
        env['LIBUSB_GIT'] = env['LIBUSB_SH'] = str(self.root / 'does-not-exist.exe')
        generate(self.source, self.out, env)
        self.assertEqual(self.out.read_bytes(), (self.source / 'build-aux/version-describe-unknown.h').read_bytes())
        reference = self.root / 'reference.h'
        shell_generate(self.source, reference)
        self.assertEqual(self.out.read_bytes(), reference.read_bytes())

    def test_frozen_tarball_and_rebuild(self):
        version = self.source / '.tarball-version'
        version.write_bytes(b' v1.2.3-test\\path"quote \r\n')
        frozen = self.source / 'build-aux/version-describe-dist.h'
        shell_generate(self.source, frozen)
        self.assertIn(b'v1.2.3-test\\\\path\\"quote', frozen.read_bytes())
        generate(self.source, self.out, bare_environment())
        self.assertEqual(self.out.read_bytes(), frozen.read_bytes())
        stamp = 1_600_000_000_000_000_000
        os.utime(self.out, ns=(stamp, stamp))
        generate(self.source, self.out, bare_environment())
        self.assertEqual(self.out.stat().st_mtime_ns, stamp)
        self.out.unlink()
        generate(self.source, self.out, bare_environment())
        self.assertEqual(self.out.read_bytes(), frozen.read_bytes())
        version.write_text('v1.2.4\n', encoding='ascii')
        shell_generate(self.source, frozen)
        generate(self.source, self.out, bare_environment())
        self.assertEqual(self.out.read_bytes(), frozen.read_bytes())

    def test_legacy_tarball_requires_shell_and_preserves_errors(self):
        version = self.source / '.tarball-version'
        version.write_text('v1.2.3\n', encoding='ascii')
        generate(self.source, self.out, bare_environment(), success=False)
        self.assertFalse(self.out.exists())
        generate(self.source, self.out)
        self.assertIn(b'"v1.2.3"', self.out.read_bytes())
        version.write_text('', encoding='ascii')
        output = generate(self.source, self.out, success=False)
        self.assertIn('empty .tarball-version', output)

    def test_git_checkout_and_worktree_precedence(self):
        source = self.checkout()
        frozen = source / 'build-aux/version-describe-dist.h'
        frozen.write_text('#define LIBUSB_DESCRIBE "stale"\n', encoding='ascii')
        expected = git('-C', str(source), 'describe', '--tags', '--always', '--dirty')
        output = generate(source, self.out)
        self.assertIn(str(OPTIONS.git_root).lower(), output.lower())
        self.assertIn(('"' + expected + '"').encode(), self.out.read_bytes())
        stamp = 1_600_000_000_000_000_000
        os.utime(self.out, ns=(stamp, stamp))
        generate(source, self.out)
        self.assertEqual(self.out.stat().st_mtime_ns, stamp)
        with (source / 'README').open('ab') as handle:
            handle.write(b'\n')
        generate(source, self.out)
        self.assertIn(b'-dirty"', self.out.read_bytes())
        linked = self.root / 'linked worktree'
        git('-C', str(source), '-c', 'core.symlinks=false', 'worktree', 'add', '--detach', str(linked), 'HEAD')
        self.assertTrue((linked / '.git').is_file())
        (linked / 'build-aux/version-describe-dist.h').write_bytes(frozen.read_bytes())
        generate(linked, self.out)
        self.assertIn(('"' + expected + '"').encode(), self.out.read_bytes())

    def test_git_failure_does_not_use_frozen_header(self):
        (self.source / '.git').write_text('gitdir: missing-git-directory\n', encoding='ascii')
        (self.source / 'build-aux/version-describe-dist.h').write_text('stale', encoding='ascii')
        output = generate(self.source, self.out, bare_environment(), success=False)
        self.assertIn('git.exe was not found', output)
        output = generate(self.source, self.out, success=False)
        self.assertIn('git describe', output)
        self.assertFalse(self.out.exists())

    def test_native_git_entry_and_explicit_paths(self):
        source = self.checkout(no_tags=True)
        entries = [OPTIONS.git_root / part / 'bin/git.exe' for part in ('mingw32', 'mingw64', 'ucrt64')]
        entry = next(path for path in entries if path.is_file())
        env = bare_environment()
        env['PATH'] = str(entry.parent) + ';' + env['PATH']
        output = generate(source, self.out, env)
        self.assertIn(str(entry).lower(), output.lower())
        self.assertRegex(self.out.read_text(), r'#define LIBUSB_DESCRIBE "[0-9a-f]{7,40}"')
        env = bare_environment()
        env['LIBUSB_GIT'] = str(entry)
        # Hosted runners have a second Git installation on their normal PATH.
        env['PATH'] = os.environ['PATH']
        output = generate(source, self.out, env)
        self.assertIn(('using git ' + str(entry)).lower(), output.lower())
        self.assertIn(('using shell ' + str(OPTIONS.git_root / 'usr/bin/sh.exe')).lower(), output.lower())
        env['LIBUSB_SH'] = str(OPTIONS.git_root / 'usr/bin/sh.exe')
        generate(source, self.out, env)
        env['LIBUSB_SH'] = str(self.root / 'missing.exe')
        self.assertIn('LIBUSB_SH', generate(source, self.out, env, success=False))

    def test_parallel_generation(self):
        (self.source / '.tarball-version').write_text('v1.2.3\n', encoding='ascii')
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: generate(self.source, self.out), range(4)))
        self.assertIn(b'"v1.2.3"', self.out.read_bytes())
        frozen = self.source / 'build-aux/version-describe-dist.h'
        shutil.copyfile(self.out, frozen)
        self.out.unlink()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: generate(self.source, self.out, bare_environment()), range(4)))
        self.assertEqual(self.out.read_bytes(), frozen.read_bytes())
        self.assertFalse(Path(str(self.out) + '.tmp').exists())


def build(source, env, target='Rebuild'):
    targets = ';'.join(f'{project}:{target}' for project in ('libusb_static', 'libusb_dll'))
    return run([OPTIONS.msbuild, source / 'msvc/libusb.sln', '/t:' + targets,
                '/p:Configuration=Release', '/p:Platform=x64', '/p:PlatformToolset=v143',
                '/m:2', '/nr:false', '/nologo', '/v:minimal'],
               env=env, cwd=source / 'msvc', timeout=300)


def check_binary(source, expected):
    dll = source / 'build/v143/x64/Release/dll/libusb-1.0.dll'
    assert (source / 'build/v143/x64/Release/lib/libusb-1.0.lib').is_file()
    code = ('import ctypes,sys; '
            'V=type("V",(ctypes.Structure,),{"_fields_":'
            '[(x,ctypes.c_uint16) for x in ("major","minor","micro","nano")]+ '
            '[("rc",ctypes.c_char_p),("describe",ctypes.c_char_p)]}); '
            'f=ctypes.WinDLL(sys.argv[1]).libusb_get_version; '
            'f.restype=ctypes.POINTER(V); print(f().contents.describe.decode())')
    assert run([sys.executable, '-c', code, dll]).strip() == expected
    quoted = str(dll).replace("'", "''")
    resource = run([PS, '-NoProfile', '-Command',
                    f"[Diagnostics.FileVersionInfo]::GetVersionInfo('{quoted}').FileVersion"])
    assert resource.strip() == expected, resource


def integration():
    expected = git('-C', str(SOURCE), 'describe', '--tags', '--always', '--dirty')
    print(build(SOURCE, tool_environment()), flush=True)
    check_binary(SOURCE, expected)
    package = WORK / 'package'
    package.mkdir()
    with tarfile.open(OPTIONS.tarball) as archive:
        archive.extractall(package, filter='data')
    source, = package.iterdir()
    frozen = source / 'build-aux/version-describe-dist.h'
    assert frozen.is_file()
    expected = (source / '.tarball-version').read_text().strip()
    env = bare_environment()
    print(build(source, env), flush=True)
    check_binary(source, expected)
    build(source, env, 'Clean')
    assert frozen.is_file()
    (source / 'libusb/version_describe.h').unlink()
    print(build(source, env), flush=True)
    check_binary(source, expected)
    frozen.unlink()
    (source / '.tarball-version').unlink()
    version = (source / 'libusb/version.h').read_text()
    version = version.replace('#define LIBUSB_RC ""', '#define LIBUSB_RC "-rc7"')
    (source / 'libusb/version.h').write_text(version)
    numbers = [re.search(r'#define LIBUSB_' + name + r' (\d+)', version)[1]
               for name in ('MAJOR', 'MINOR', 'MICRO')]
    rc = re.search(r'#define LIBUSB_RC "([^"]*)"', version)[1]
    expected = 'Unknown source (v' + '.'.join(numbers) + rc + ')'
    print(build(source, env), flush=True)
    check_binary(source, expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git-root', type=Path, required=True)
    parser.add_argument('--sourcetree', action='store_true', help='Discover Git from the SourceTree profile layout, off PATH')
    parser.add_argument('--mingit', action='store_true', help='Require a distribution without bash.exe or cygpath.exe')
    parser.add_argument('--msbuild', type=Path)
    parser.add_argument('--tarball', type=Path)
    OPTIONS = parser.parse_args()
    if os.name != 'nt':
        parser.error('Run with native Windows Python and Windows PowerShell 5.1.')
    if bool(OPTIONS.msbuild) != bool(OPTIONS.tarball):
        parser.error('--msbuild and --tarball must be supplied together')
    OPTIONS.git_root = OPTIONS.git_root.resolve()
    if OPTIONS.sourcetree:
        assert tuple(part.lower() for part in OPTIONS.git_root.parts[-3:]) == ('atlassian', 'sourcetree', 'git_local')
    if OPTIONS.mingit:
        assert not list(OPTIONS.git_root.rglob('bash.exe'))
        assert not list(OPTIONS.git_root.rglob('cygpath.exe'))
    base = (SOURCE / 'build').resolve()
    base.mkdir(exist_ok=True)
    WORK = Path(tempfile.mkdtemp(prefix='version-tests-', dir=base)).resolve()
    assert WORK.is_relative_to(base)
    print('Test workspace:', WORK, flush=True)
    assert run([PS, '-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()']).strip().startswith('5.1.')
    run([PS, '-NoProfile', '-Command',
         'if (Get-Command git.exe,bash.exe,sh.exe,cygpath.exe,wsl.exe -CommandType Application '
         '-ErrorAction SilentlyContinue) { throw "The restricted PATH contains external tools" }'],
        env=bare_environment())
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(VersionTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if OPTIONS.msbuild:
        integration()
    print('Version tests passed.', flush=True)
