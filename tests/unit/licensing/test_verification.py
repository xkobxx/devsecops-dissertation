import unittest


class LicenceVerificationTests(unittest.TestCase):
    def test_missing_key_is_an_explicit_free_tier_result(self):
        from trustgate.licensing import verify

        valid, reason, payload = verify("")

        self.assertFalse(valid)
        self.assertEqual(reason, "no license key provided")
        self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
