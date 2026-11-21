import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('deb_builder', ROOT / 'packaging/build-deb.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ServiceStateGuards(unittest.TestCase):
    def test_manifest_records_real_version_without_assuming_commit_equality(self):
        for version in ('v0.0.0-20261116031906-3b8403344202', '1.2.3', 'a' * 40):
            with patch.object(builder, 'run', return_value=version):
                self.assertEqual(builder.executable_version(Path('/test/runnerd'), source_dirty=False), version)
        for version in ('development', '', 'v0.0.0+dirty', 'bad\nversion'):
            with patch.object(builder, 'run', return_value=version):
                with self.assertRaises(ValueError):
                    builder.executable_version(Path('/test/runnerd'), source_dirty=False)

    def test_local_working_tree_build_records_dirty_version(self):
        with patch.object(builder, 'run', return_value='v0.0.0+dirty'):
            self.assertEqual(builder.executable_version(Path('/test/runnerd'), source_dirty=True), 'v0.0.0+dirty')

    def test_upgrade_preserves_configured_groups_and_rejects_root_identity(self):
        # Run the actual account guard with a controlled OS identity database.
        account_guard = 'if getent passwd' + (ROOT / 'packaging/debian/preinst').read_text().split('if getent passwd', 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            getent = Path(directory) / 'getent'
            getent.write_text('#!/bin/sh\nexit 0\n')
            getent.chmod(0o755)
            identity = Path(directory) / 'id'
            identity.write_text('#!/bin/sh\n[ "${TEST_LOOKUP_FAILURE:-0}" = 0 ] || exit 1\ncase "$1" in\n-u) echo "$TEST_UID";;\n-g) echo "$TEST_GID";;\n-G) echo "$TEST_GROUPS";;\n*) exit 1;;\nesac\n')
            identity.chmod(0o755)
            for uid, gid, groups, allowed in (
                    ('982', '982', '982', True),
                    ('982', '982', '982 983', True),
                    ('982', '982', '982 983 44', True),
                    ('0', '982', '982 983', False),
                    ('982', '0', '982 983', False),
                    ('982', '982', '982 983 0', False),
                    ('982', '982', '', False),
                    ('982', '982', 'invalid', False),
                    ('', '982', '982', False),
                    ('982', '', '982', False)):
                with self.subTest(uid=uid, gid=gid, groups=groups):
                    result = subprocess.run(['/bin/sh', '-ec', account_guard],
                        env={**os.environ, 'PATH': directory, 'TEST_UID': uid, 'TEST_GID': gid, 'TEST_GROUPS': groups},
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
            failed_lookup = subprocess.run(['/bin/sh', '-ec', account_guard],
                env={**os.environ, 'PATH': directory, 'TEST_LOOKUP_FAILURE': '1'},
                capture_output=True, text=True)
            self.assertNotEqual(failed_lookup.returncode, 0)

    def guard(self, state, code=0):
        with tempfile.TemporaryDirectory() as directory:
            systemctl = Path(directory) / 'systemctl'
            systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_STATE"\nexit "$TEST_CODE"\n')
            systemctl.chmod(0o755)
            content = (ROOT / 'packaging/debian/service-state.sh').read_text()
            return subprocess.run(['/bin/sh', '-c', content + '\nrunnerd_require_stopped'],
                                  env={**os.environ, 'PATH': directory, 'TEST_STATE': state, 'TEST_CODE': str(code)},
                                  capture_output=True, text=True)

    def state(self, active='inactive', main='0', control='0', load='loaded'):
        return f'LoadState={load}\nActiveState={active}\nMainPID={main}\nControlPID={control}'

    def test_stopped_or_absent_unit_is_allowed(self):
        for state in (self.state(), self.state(active='failed'), self.state(load='not-found')):
            self.assertEqual(self.guard(state).returncode, 0)

    def test_running_or_transitioning_service_is_rejected(self):
        for active in ('active', 'activating', 'deactivating', 'reloading', 'maintenance', 'unknown', ''):
            with self.subTest(active=active):
                self.assertNotEqual(self.guard(self.state(active=active)).returncode, 0)

    def test_live_main_or_control_process_is_rejected(self):
        for state in (self.state(main='123'), self.state(control='456'), self.state(main=''), self.state(load='error')):
            self.assertNotEqual(self.guard(state).returncode, 0)

    def test_failed_or_incomplete_query_never_means_stopped(self):
        for state, code in (('', 1), (self.state(), 1), ('ActiveState=inactive', 0)):
            self.assertNotEqual(self.guard(state, code).returncode, 0)

    def test_both_scripts_embed_the_same_guard_before_changes(self):
        for name in ('preinst', 'prerm'):
            script = builder.maintainer_script(ROOT, name)
            self.assertNotIn('# RUNNERD_SERVICE_GUARD', script)
            self.assertEqual(script.count('runnerd_require_stopped()'), 1)
            subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True)
            self.assertLess(script.index('runnerd_require_stopped;'), script.index('systemctl disable') if name == 'prerm' else script.index('if getent'))
