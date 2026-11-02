"""WAF policy exceptions: conditions apply together and an asset condition limits the websites affected."""

import unittest

from securityhub.scanners.waf.checks import assess_exception, check_waf


def exc(*conds, comment="created by events p"):
    return {"comment": comment, "data": [{"exceptionType": t, "values": v} for t, v in conds]}


def policy(*excs):
    return [{"id": 1, "name": "Global WAF", "policyType": "WAF_RULES", "enabled": True, "policySettings": [
        {"policySettingType": "SQL_INJECTION", "settingsAction": "BLOCK", "policyDataExceptions": list(excs)}]}]


class ExceptionTest(unittest.TestCase):
    def test_asset_condition_limits_the_exception(self):
        e = exc(("COUNTRY", ["Italy"]), ("URL", ["/stg/wp/wp-admin/"]), ("SITE_ID", ["12970686"]))
        self.assertIsNone(assess_exception(e, 999))                       # another website: not applied
        got = assess_exception(e, 12970686)
        self.assertEqual((got["scope"], got["broad"]), ("asset 12970686", False))  # country AND specific URL
        site = check_waf({"site_id": 999}, policy(e))
        self.assertEqual(site.data["exception_count"], 0)
        self.assertNotIn("WAF_BROAD_EXCEPTION", {i.code for i in site.issues})
        self.assertEqual(site.data["rules"][0]["exceptions"], 0)

    def test_broad_only_without_narrowing_condition(self):
        self.assertTrue(assess_exception(exc(("COUNTRY", ["Italy"]), ("SITE_ID", ["5"])), "5")["broad"])
        self.assertTrue(assess_exception(exc(("URL", ["/"]), ("IP", ["10.0.0.0/8"])), 5)["broad"])
        self.assertTrue(assess_exception(exc(), 5)["broad"])
        self.assertFalse(assess_exception(exc(("IP", ["103.53.119.250"]), ("URL", ["/stg/en-au/wp-admin/post.php"])), 5)["broad"])
        self.assertFalse(assess_exception(exc(("COUNTRY", ["Italy"]), ("PARAMETER", ["q"])), 5)["broad"])
        site = check_waf({"site_id": 5}, policy(exc(("COUNTRY", ["Italy"]), ("SITE_ID", ["5"]))))
        issue = [i for i in site.issues if i.code == "WAF_BROAD_EXCEPTION"][0]
        self.assertIn("whole country", issue.message)
