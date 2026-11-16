"""Exercise the full release-verification CLI used by the publish workflow."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import network_logging_policy
import carpets_recipe_policy
import waypoint_source_policy
import shutil
import zipfile
import multiplayer_warning_policy as warning
from generate_manifest import generate
import public_server_policy


class ReleaseVerificationTests(unittest.TestCase):
    def test_reapplies_advisory_setting_in_staged_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            pack = Path(temporary)
            (pack / "portable-pack.json").write_text(json.dumps(waypoint_source_policy.PLATFORM))
            metadata = b'{"mainProfile":"Updated","hashes":{"Updated/options.txt":"author marker"}}'
            relative = "config/defaultsettings/Updated/options.txt"
            options = pack / relative
            options.parent.mkdir(parents=True)
            (pack / warning.PROFILE).write_bytes(metadata)
            personal = pack / "options.txt"
            personal.write_bytes(b"fov:0.5\n")
            for original, expected in [
                (b"fov:0.7\r\nskipMultiplayerWarning:false\r\nlang:ru_ru",
                 b"fov:0.7\r\nskipMultiplayerWarning:true\r\nlang:ru_ru"),
                (b"fov:0.7\r\nlang:ru_ru\r\n", b"fov:0.7\r\nlang:ru_ru\r\nskipMultiplayerWarning:true\r\n"),
                (b"skipMultiplayerWarning:true\nfov:0.8\n", b"skipMultiplayerWarning:true\nfov:0.8\n"),
                (b"fov:0.6", b"fov:0.6\nskipMultiplayerWarning:true\n"),
            ]:
                with self.subTest(original=original):
                    options.write_bytes(original)
                    dist = pack / "dist"
                    generate(pack, dist, "fixture")
                    manifest = json.loads((dist / "pack-manifest.json").read_bytes())
                    warning.verify(dist, manifest)
                    gate = pack / "reviewed.json"
                    gate.write_text(json.dumps({
                        "schemaVersion": 1, "policy": public_server_policy.POLICY,
                        "reviewedInventorySha256": public_server_policy.inventory_sha256(manifest["files"])
                    }))
                    self.assertEqual("PASS", public_server_policy.verify(pack, manifest, gate)["status"])
                    asset = next(row for row in manifest["assets"] if relative in row["covers"])
                    with zipfile.ZipFile(dist / "assets" / asset["name"]) as archive:
                        self.assertEqual(expected, archive.read(relative))
                        self.assertEqual(metadata, archive.read(warning.PROFILE))
                    self.assertEqual(original, options.read_bytes())
                    self.assertEqual(b"fov:0.5\n", personal.read_bytes())
                    self.assertNotIn("options.txt", {row["path"] for row in manifest["files"]})
                    for invalid in (b"skipMultiplayerWarning:false\n", b"fov:0.5\n"):
                        with zipfile.ZipFile(dist / "assets" / asset["name"], "w") as archive:
                            archive.writestr(warning.PROFILE, metadata)
                            archive.writestr(relative, invalid)
                        row = next(row for row in manifest["files"] if row["path"] == relative)
                        row.update(sizeBytes=len(invalid), sha256=hashlib.sha256(invalid).hexdigest())
                        with self.assertRaisesRegex(ValueError, "must set skipMultiplayerWarning:true"):
                            warning.verify(dist, manifest)

    def test_verify_all_checks_assets_beyond_the_sample_without_generating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / 'source'
            pack.mkdir()
            (pack / 'config').mkdir()
            source = Path(__file__).resolve().parents[1]
            (pack / 'config/log4j2.xml').write_bytes((source / 'config/log4j2.xml').read_bytes())
            version = json.loads((source / 'portable-pack.json').read_text(encoding='utf-8-sig'))['minecraftVersion']
            (pack / 'portable-pack.json').write_text(json.dumps(waypoint_source_policy.PLATFORM), encoding='utf-8')
            network_logging_policy.prepare(pack)
            # The publication CLI also requires the source-owned recipe policy.
            jar = 'mods/alchemistry-1.20.1-2.3.4.jar'
            (pack / 'mods').mkdir()
            shutil.copyfile(source / jar, pack / jar)
            shutil.copyfile(source / 'launcher/pack-owned.txt', pack / 'launcher/pack-owned.txt')
            carpets_recipe_policy.prepare(pack)
            for relative in [waypoint_source_policy.SCRIPT, waypoint_source_policy.TEMPLATE,
                             waypoint_source_policy.RECEIPT, 'tools/client-policy/policy.json']:
                target = pack / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target)
            native = json.loads((source / waypoint_source_policy.RECEIPT).read_bytes())['nativeModules']
            for row in native:
                shutil.copyfile(source / row['path'], pack / row['path'])
            dist = root / 'dist'
            assets = dist / 'assets'
            assets.mkdir(parents=True)
            rows = []
            for index in range(11):
                payload = bytes([index])
                name = f'asset-{index}.bin'
                (assets / name).write_bytes(payload)
                rows.append({'name': name, 'sizeBytes': len(payload), 'covers': [],
                             'sha256': hashlib.sha256(payload).hexdigest()})
            relative = 'config/defaultsettings/Default/options.txt'
            options = b'skipMultiplayerWarning:true\n'
            metadata = b'{"mainProfile":"Default"}'
            config = assets / 'config.zip'
            with zipfile.ZipFile(config, 'w') as archive:
                archive.writestr(warning.PROFILE, metadata)
                archive.writestr(relative, options)
            rows.append({'name': config.name, 'kind': 'zipRoot', 'sizeBytes': config.stat().st_size,
                         'sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
                         'covers': [warning.PROFILE, relative]})
            manifest = dist / 'pack-manifest.json'
            manifest.write_text(json.dumps({**waypoint_source_policy.PLATFORM, 'assets': rows, 'files': [
                {'path': path, 'sizeBytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for path, raw in [(relative, options), (warning.PROFILE, metadata)]
            ]}), encoding='utf-8')
            original_manifest = manifest.read_bytes()
            command = [sys.executable, str(Path(__file__).with_name('generate_manifest.py')),
                       '--pack', str(pack), '--out', str(dist), '--verify-all']
            passed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, passed.returncode, passed.stdout + passed.stderr)
            self.assertIn('verified 12 of 12 staged assets', passed.stdout)
            self.assertEqual(original_manifest, manifest.read_bytes())
            receipt = pack / 'tools/network-logging-policy.json'
            pinned = receipt.read_bytes()
            receipt.unlink()
            no_policy = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(0, no_policy.returncode)
            self.assertIn('network logging policy invalid', no_policy.stderr)
            self.assertEqual(original_manifest, manifest.read_bytes())
            receipt.write_bytes(pinned)
            recipe_receipt = pack / carpets_recipe_policy.RECEIPT
            recipe_pinned = recipe_receipt.read_bytes()
            recipe_receipt.unlink()
            no_recipe_policy = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(0, no_recipe_policy.returncode)
            self.assertIn('carpets recipe policy invalid', no_recipe_policy.stderr)
            self.assertEqual(original_manifest, manifest.read_bytes())
            recipe_receipt.write_bytes(recipe_pinned)
            waypoint_receipt = pack / waypoint_source_policy.RECEIPT
            waypoint_pinned = waypoint_receipt.read_bytes()
            waypoint_receipt.unlink()
            no_waypoint_policy = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(0, no_waypoint_policy.returncode)
            self.assertIn('waypoint generation policy invalid', no_waypoint_policy.stderr)
            self.assertEqual(original_manifest, manifest.read_bytes())
            waypoint_receipt.write_bytes(waypoint_pinned)
            for row in rows:
                asset = assets / row['name']
                original = asset.read_bytes()
                asset.write_bytes(b'X')
                failed = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(0, failed.returncode, row['name'])
                self.assertIn('hash/size mismatch', failed.stderr)
                self.assertEqual(original_manifest, manifest.read_bytes())
                asset.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
