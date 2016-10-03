import ldap
from ldap.controls import SimplePagedResultsControl

SERVER = "dc.example.net"
USERNAME = "ADLookup"
PASSWORD = "12345LuggageAmazing"
BASE = "dc=example, dc=net"
FILTER = "(sAMAccountName=sean.whalen)"
PAGE_SIZE = 1000

ad = ldap.initialize("ldap://{0}".format(SERVER), trace_level=2)
ad.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
ad.set_option(ldap.OPT_REFERRALS, 0)

ad.simple_bind(USERNAME, PASSWORD)

pc = SimplePagedResultsControl(criticality=True, size=PAGE_SIZE, cookie="")

msgid = ad.search_ext(BASE,
                      scope=ldap.SCOPE_SUBTREE,
                      filterstr=FILTER,
                      clientctrls=[pc])

# Skipping over processing because it the exception is raised at the above call
