"""
FixAI Improvement #9 — RUL Hardware Life Predictor Test Suite
=============================================================

Tests for:
- Battery capacity retention, wear percentage, and cycle degradation
- Arrhenius thermal degradation acceleration on lithium-ion cells
- Storage SSD/NVMe Terabytes Written (TBW) endurance exhaustion
- S.M.A.R.T. bad block / reallocated sector penalties
- Holistic multi-component hardware RUL scoring and maintenance advisories
- Serialization and dataclass integrity
"""

import os
import sys
import unittest

# Ensure the local_agent package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai_engine.rul_predictor import (
    RULPredictor,
    BatteryHealth,
    StorageHealth,
    RULPredictionResult,
)


class TestBatteryRULPhysics(unittest.TestCase):
    """Tests for electrochemical battery degradation modeling."""

    def setUp(self):
        self.predictor = RULPredictor()

    def test_pristine_battery(self):
        """New battery should report 100% health and EXCELLENT status."""
        b = self.predictor.predict_battery_rul(
            cycle_count=5,
            design_mwh=60000.0,
            current_mwh=60000.0,
            temp_c=25.0,
        )
        self.assertAlmostEqual(b.capacity_percent, 100.0)
        self.assertAlmostEqual(b.wear_level_percent, 0.0)
        self.assertEqual(b.health_status, "EXCELLENT")
        self.assertGreater(b.estimated_remaining_cycles, 400)
        self.assertGreater(b.estimated_remaining_months, 15.0)

    def test_moderate_battery_wear(self):
        """Battery with 90% health should be EXCELLENT/GOOD with ~10% wear."""
        b = self.predictor.predict_battery_rul(
            cycle_count=120,
            design_mwh=50000.0,
            current_mwh=45000.0,
            temp_c=28.0,
        )
        self.assertAlmostEqual(b.capacity_percent, 90.0)
        self.assertAlmostEqual(b.wear_level_percent, 10.0)
        self.assertIn(b.health_status, ("EXCELLENT", "GOOD"))

    def test_degraded_battery_fair_status(self):
        """Battery at 75% health should be FAIR."""
        b = self.predictor.predict_battery_rul(
            cycle_count=350,
            design_mwh=50000.0,
            current_mwh=37500.0,
            temp_c=30.0,
        )
        self.assertAlmostEqual(b.capacity_percent, 75.0)
        self.assertEqual(b.health_status, "FAIR")

    def test_critical_replace_status(self):
        """Battery below 60% capacity must require CRITICAL replacement."""
        b = self.predictor.predict_battery_rul(
            cycle_count=650,
            design_mwh=50000.0,
            current_mwh=27500.0,
            temp_c=33.0,
        )
        self.assertLess(b.capacity_percent, 60.0)
        self.assertEqual(b.health_status, "CRITICAL_REPLACE")

    def test_arrhenius_thermal_acceleration(self):
        """High operating temperatures should reduce remaining cycles."""
        cool_b = self.predictor.predict_battery_rul(
            cycle_count=100,
            design_mwh=50000.0,
            current_mwh=45000.0,
            temp_c=25.0,  # 25°C
        )
        hot_b = self.predictor.predict_battery_rul(
            cycle_count=100,
            design_mwh=50000.0,
            current_mwh=45000.0,
            temp_c=45.0,  # 45°C elevated thermal envelope
        )
        self.assertGreater(cool_b.estimated_remaining_cycles, hot_b.estimated_remaining_cycles)
        self.assertGreater(cool_b.estimated_remaining_months, hot_b.estimated_remaining_months)

    def test_bounds_safety(self):
        """Negative or zero values should be safely clamped."""
        b = self.predictor.predict_battery_rul(
            cycle_count=-10,
            design_mwh=-500,
            current_mwh=-200,
        )
        self.assertGreaterEqual(b.capacity_percent, 0.0)
        self.assertGreaterEqual(b.estimated_remaining_cycles, 0)


class TestStorageRULPhysics(unittest.TestCase):
    """Tests for SSD endurance and S.M.A.R.T. health modeling."""

    def setUp(self):
        self.predictor = RULPredictor()

    def test_optimal_ssd(self):
        """Fresh SSD with minimal TBW should be OPTIMAL with years of endurance."""
        s = self.predictor.predict_storage_rul(
            drive_name="NVMe 1TB",
            tbw_written=10.0,
            tbw_limit=600.0,
            reallocated_sectors=0,
            daily_write_gb=20.0,
        )
        self.assertGreater(s.health_percent, 95.0)
        self.assertEqual(s.health_status, "OPTIMAL")
        self.assertGreater(s.estimated_remaining_days, 1000)

    def test_tbw_wear_depletion(self):
        """SSD near TBW endurance limit should drop in health."""
        s = self.predictor.predict_storage_rul(
            drive_name="NVMe 1TB",
            tbw_written=500.0,
            tbw_limit=600.0,
            reallocated_sectors=0,
        )
        self.assertLess(s.health_percent, 25.0)
        self.assertIn(s.health_status, ("WARNING", "CRITICAL_REPLACE"))

    def test_reallocated_sectors_penalty(self):
        """Reallocated sectors should apply penalty to health score."""
        clean = self.predictor.predict_storage_rul(
            tbw_written=50.0,
            tbw_limit=300.0,
            reallocated_sectors=0,
        )
        damaged = self.predictor.predict_storage_rul(
            tbw_written=50.0,
            tbw_limit=300.0,
            reallocated_sectors=5,
        )
        self.assertGreater(clean.health_percent, damaged.health_percent)

    def test_storage_bounds_safety(self):
        """Excess TBW written beyond limit should not crash or go negative."""
        s = self.predictor.predict_storage_rul(
            tbw_written=1000.0,
            tbw_limit=300.0,
            reallocated_sectors=20,
        )
        self.assertEqual(s.health_percent, 0.0)
        self.assertEqual(s.estimated_remaining_days, 0)
        self.assertEqual(s.health_status, "CRITICAL_REPLACE")


class TestHolisticHardwareRUL(unittest.TestCase):
    """Tests for multi-component hardware diagnostics."""

    def setUp(self):
        self.predictor = RULPredictor()

    def test_healthy_laptop_overall(self):
        result = self.predictor.predict_hardware_rul(
            battery_kwargs={"cycle_count": 50, "design_mwh": 60000.0, "current_mwh": 57000.0},
            storage_kwargs={"tbw_written": 20.0, "tbw_limit": 600.0, "reallocated_sectors": 0},
        )
        self.assertIsInstance(result, RULPredictionResult)
        self.assertGreater(result.overall_hardware_score, 85.0)
        self.assertEqual(result.hardware_status, "HEALTHY")
        self.assertGreater(len(result.recommendations), 0)

    def test_degraded_battery_recommendation(self):
        result = self.predictor.predict_hardware_rul(
            battery_kwargs={"cycle_count": 700, "design_mwh": 50000.0, "current_mwh": 25000.0},  # 50%
            storage_kwargs={"tbw_written": 20.0, "tbw_limit": 600.0},
        )
        self.assertIn("CRITICAL_REPLACE", result.battery.health_status)
        self.assertTrue(any("replacement" in r.lower() for r in result.recommendations))

    def test_smart_bad_sector_recommendation(self):
        result = self.predictor.predict_hardware_rul(
            battery_kwargs={"cycle_count": 50, "design_mwh": 60000.0, "current_mwh": 58000.0},
            storage_kwargs={"reallocated_sectors": 3},
        )
        self.assertTrue(any("S.M.A.R.T." in r for r in result.recommendations))
        self.assertTrue(any("backup" in r.lower() for r in result.recommendations))

    def test_to_dict_serialization(self):
        result = self.predictor.predict_hardware_rul()
        d = result.to_dict()
        self.assertIn("overall_hardware_score", d)
        self.assertIn("battery", d)
        self.assertIn("storage", d)
        self.assertIn("recommendations", d)
        self.assertIsInstance(d["recommendations"], list)
        self.assertIn("capacity_percent", d["battery"])
        self.assertIn("health_percent", d["storage"])


if __name__ == "__main__":
    unittest.main()
