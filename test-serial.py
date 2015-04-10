from serial import SerialNumber, InvalidSerialNumberOperationError

import unittest

class SerialNumberTest(unittest.TestCase):
    def test_increment_by_one_without_wrap(self):
        n = SerialNumber(100, 8)
        self.assertEqual(n + 1, 101)
        self.assertEqual(1 + n, 101)

    def test_increment_by_one_with_wrap(self):
        n = SerialNumber(255, 8)
        self.assertEqual(n + 1, 0)
        self.assertEqual(1 + n, 0)

    def test_increment_by_some_without_wrap(self):
        n = SerialNumber(100, 8)
        self.assertEqual(n + 50, 150)
        self.assertEqual(50 + n, 150)

    def test_increment_by_some_with_wrap(self):
        n = SerialNumber(250, 8)
        self.assertEqual(n + 20, 14)
        self.assertEqual(20 + n, 14)

    def test_increment_by_too_much(self):
        n = SerialNumber(100, 8)
        with self.assertRaises(InvalidSerialNumberOperationError):
            n + 129

        with self.assertRaises(InvalidSerialNumberOperationError):
            129 + n

    def test_equality_with_same_serial_bits(self):
        n = SerialNumber(1000, 16)
        m = SerialNumber(1000, 16)
        self.assertEqual(n, m)
        self.assertNotEqual(n, m)

    def test_equality_with_different_serial_bits(self):
        n = SerialNumber(1000, 16)
        m = SerialNumber(1000, 24)
        self.assertTrue(n != m)
        self.assertFalse(n == m)

    def test_comparison(self):
        n0 = SerialNumber(0, 8)
        n1 = SerialNumber(1, 8)
        n44 = SerialNumber(44, 8)
        n100 = SerialNumber(100, 8)
        n200 = SerialNumber(200, 8)
        n255 = SerialNumber(255, 8)

        self.assertTrue(n1 > n0)
        self.assertTrue(n0 < n1)
        self.assertFalse(n1 < n0)
        self.assertFalse(n0 > n1)

        self.assertTrue(n44 > n0)
        self.assertTrue(n0 < n44)
        self.assertFalse(n44 < n0)
        self.assertFalse(n0 > n44)

        self.assertTrue(n100 > n0)
        self.assertTrue(n0 < n100)
        self.assertFalse(n100 < n0)
        self.assertFalse(n0 > n100)

        self.assertTrue(n100 > n44)
        self.assertTrue(n44 < n100)
        self.assertFalse(n100 < n44)
        self.assertFalse(n44 > n100)

        self.assertTrue(n200 > n100)
        self.assertTrue(n100 < n200)
        self.assertFalse(n200 < n100)
        self.assertFalse(n100 > n200)

        self.assertTrue(n255 > n200)
        self.assertTrue(n200 < n255)
        self.assertFalse(n255 < n200)
        self.assertFalse(n200 > n255)

        self.assertTrue(n0 > n255)
        self.assertTrue(n255 < n0)
        self.assertFalse(n0 < n255)
        self.assertFalse(n255 > n0)

        self.assertTrue(n100 > n255)
        self.assertTrue(n255 < n100)
        self.assertFalse(n100 < n255)
        self.assertFalse(n255 > n100)

        self.assertTrue(n0 > n200)
        self.assertTrue(n200 < n0)
        self.assertFalse(n0 < n200)
        self.assertFalse(n200 > n0)

        self.assertTrue(n44 > n200)
        self.assertTrue(n200 < n44)
        self.assertFalse(n44 < n200)
        self.assertFalse(n200 > n44)

if __name__ == '__main__':
    unittest.main()
