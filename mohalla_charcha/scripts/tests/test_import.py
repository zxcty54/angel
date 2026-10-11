import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1]/'import_locations.py'
spec = importlib.util.spec_from_file_location('import_locations', SCRIPT)
locations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(locations)
HEADER = ','.join(locations.COLUMNS)+'\n'


class ImportTests(unittest.TestCase):
    def render(self, rows):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)/'locations.csv'; path.write_text(HEADER+rows)
            return locations.render_import(path)

    def test_urban_null_panchayat_and_escaped_alias(self):
        sql = self.render("Patna,urban,Test ULB,,22,Neighbour's lane,25.6,85.1\n")
        self.assertIn("NULL,22,'Neighbour''s lane'", sql)
        self.assertIn('ON CONFLICT ON CONSTRAINT location_full_path', sql)

    def test_rural_requires_panchayat(self):
        with self.assertRaisesRegex(ValueError, 'panchayat'):
            self.render('Patna,rural,Bikram,,4,Sample,,\n')

    def test_duplicate_full_path_rejected_but_same_ward_different_panchayat_valid(self):
        row='Patna,rural,Bikram,Danara,4,Sample,,\n'
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.render(row+row)
        self.assertIn('Mahajpura', self.render(row+'Patna,rural,Bikram,Mahajpura,4,Sample,,\n'))

    def test_partial_or_nonfinite_coordinates_rejected(self):
        with self.assertRaisesRegex(ValueError, 'both'): self.render('Patna,urban,Test ULB,,22,Sample,25.6,\n')
        with self.assertRaisesRegex(ValueError, 'finite'): self.render('Patna,urban,Test ULB,,22,Sample,nan,85.1\n')

    def test_template_is_not_a_fake_dataset(self):
        with self.assertRaisesRegex(ValueError, 'No location rows'): self.render('')


if __name__ == '__main__': unittest.main()
