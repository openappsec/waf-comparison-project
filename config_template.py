from sqlalchemy import create_engine
from pathlib import Path

# Database configuration
engine = create_engine(rf"sqlite:///waf_comparison.db")

# Data set paths
LEGITIMATE_URL_PATH = "https://downloads.openappsec.io/waf-comparison-project/legitimate.zip"
MALICIOUS_URL_PATH = "https://downloads.openappsec.io/waf-comparison-project/malicious.zip"

# Data set Path
DATA_PATH = Path('Data')
LEGITIMATE_PATH = DATA_PATH / 'Legitimate'
MALICIOUS_PATH = DATA_PATH / 'Malicious'

# WAF configuration
WAFS_DICT = {
    "AWS WAF - Default AWS Rules":                          'http://Fill in your waf url.com',
    "AWS WAF - AWS and F5 Rules":                           'http://Fill in your waf url.com',
    "Azure WAF - OWASP 3.2 Rule set":                       'http://Fill in your waf url.com',
    "open-appsec/CloudGuard AppSec - Critical Profile":     'http://Fill in your waf url.com',
    "open-appsec/CloudGuard AppSec - Default Profile":      'http://Fill in your waf url.com',
    "NGINX ModSecurity - Default":                          'http://Fill in your waf url.com',
    "NGINX AppProtect - Default":                           'http://Fill in your waf url.com',
    "NGINX AppProtect - Strict Profile":                    'http://Fill in your waf url.com',
    "CloudFlare - Managed and OWASP Core Rulesets":         'http://Fill in your waf url.com',
}
