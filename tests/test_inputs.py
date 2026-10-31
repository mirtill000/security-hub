"""Domain list input: a plain list is enough; metadata columns are optional."""

from securityhub.scanners.dns_email.inputs import load_domains

from .helpers import TempDirTest


class DomainInputTest(TempDirTest):
    def load(self, text, name="domains.csv"):
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        items, invalid = load_domains(p)
        return [(d.domain, d.tier, d.owner, d.bu, d.tags) for d in items], invalid

    def test_plain_list_even_with_csv_extension(self):
        items, bad = self.load("esempio.it\nEsempio.COM.\n\n# commento\nwww.esempio.org  # sito\nesempio.it\n")
        self.assertEqual([d for d, *_ in items], ["esempio.it", "esempio.com", "www.esempio.org"])
        self.assertTrue(all(t == "medium" for _, t, *_ in items))
        self.assertEqual(bad, [])

    def test_several_domains_per_line(self):
        items, _ = self.load("a.it, b.it c.it;d.it\n", "domains.txt")
        self.assertEqual([d for d, *_ in items], ["a.it", "b.it", "c.it", "d.it"])

    def test_header_any_order_and_italian_names(self):
        items, _ = self.load("referente;dominio;criticità\nit-sec;esempio.it;critical\n;banca.it;\n")
        self.assertEqual(items, [("esempio.it", "critical", "it-sec", "", []), ("banca.it", "medium", "", "", [])])

    def test_no_header_positional_optional_columns(self):
        items, _ = self.load("esempio.it;critical;it-sec;corp;brand|mail\nesempio.com;;marketing\nesempio.org\n")
        self.assertEqual(items, [("esempio.it", "critical", "it-sec", "corp", ["brand", "mail"]),
                                 ("esempio.com", "medium", "marketing", "", []),
                                 ("esempio.org", "medium", "", "", [])])

    def test_invalid_entries_are_reported(self):
        items, bad = self.load("esempio.it\nnon_valido!\n")
        self.assertEqual([d for d, *_ in items], ["esempio.it"])
        self.assertEqual(bad, ["non_valido!"])

    def test_empty_file(self):
        self.assertEqual(self.load("# solo commenti\n\n"), ([], []))
