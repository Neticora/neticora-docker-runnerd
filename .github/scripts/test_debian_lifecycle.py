import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('deb_builder', ROOT / 'packaging/build-deb.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ServiceStateGuards(unittest.TestCase):
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
